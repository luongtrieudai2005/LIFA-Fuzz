"""
slow_loop/state_machine_inferer.py
──────────────────────────────────
Veritas-inspired Probabilistic Protocol State Machine (P-PSM) inference from
network traces. PURE BLACK-BOX: no source code, no protocol specification,
no hardcoded keywords. Works on any text or binary protocol.

Reference:
    Wang, Y. et al., "Inferring Protocol State Machine from Network Traces:
    A Probabilistic Approach" (Veritas), 2011.

Algorithm (4 steps, all statistical):
    1. Message format extraction: 3-byte units from packet headers → K-S test
       filter → reconstruct format messages (units combiner).
    2. State message clustering: PAM (Partitioning Around Medoids) + Jaccard
       similarity → cluster centers = state message types. Optimal k via Dunn.
    3. State labeling: each packet → nearest medoid (or "unknown").
    4. State machine inference: DFA from session state-type sequences +
       transition probabilities → P-PSM.

Integration: Slow Loop runs this alongside DifferentialAnalyzer (same captured
traffic input). Output P-PSM → shared/state_machine.json → Fast Loop's
InferredStateTracker reads it → generic state tracking for ANY protocol.

Pure Python — no scipy/sklearn dependency (K-S test + PAM implemented here).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from shared.logger import get_logger

log = get_logger("slow_loop.state_machine_inferer")

# ===========================================================================
# Data structures
# ===========================================================================


@dataclass
class ProbabilisticStateMachine:
    """P-PSM — an inferred protocol state machine.

    Attributes:
        medoids:   list of medoid packet headers (bytes), one per state type.
        features:  256-dim byte-frequency vectors for each medoid (for labeling).
        transitions: dict[(state_i, state_j)] → probability, from sessions.
        cluster_diameters: max intra-cluster distance per state (for unknown label).
    """

    medoids: list[bytes] = field(default_factory=list)
    features: list[list[int]] = field(default_factory=list)
    transitions: dict[tuple[int, int], float] = field(default_factory=dict)
    cluster_diameters: list[float] = field(default_factory=list)
    n_states: int = 0

    def label_packet(self, packet: bytes) -> Optional[int]:
        """Label a packet with the nearest medoid state type.

        Returns the state index (0-based), or None if "unknown" (too far from
        all medoids — e.g. a pure-data packet with no protocol header).

        Uses GLOBAL d_max = 2 * max(cluster_diameters) per Veritas spec,
        NOT per-cluster diameter. Per-cluster would let singleton clusters
        (diameter=0) accept any packet including garbage.
        """
        if not packet or not self.medoids or not self.features:
            return None
        feat = _byte_frequency_vector(packet[:12])
        best_idx = -1
        best_dist = float("inf")
        for i, med_feat in enumerate(self.features):
            d = _jaccard_distance(feat, med_feat)
            if d < best_dist:
                best_dist = d
                best_idx = i
        if best_idx < 0:
            return None
        # Global d_max (Veritas §3.4): max over ALL clusters of 2*Δ(C_i).
        # Cap at 0.75 — Jaccard distance max is 1.0, so d_max > 1.0 means
        # NO filtering (everything accepted). With coarse clusters (large
        # diameter), uncapped d_max would accept garbage packets.
        global_d_max = 2 * max(self.cluster_diameters) if self.cluster_diameters else 0.5
        global_d_max = min(global_d_max, 0.75)
        if global_d_max == 0:
            global_d_max = 0.5  # singleton-only fallback
        if best_dist > global_d_max:
            return None
        return best_idx

    def to_dict(self) -> dict[str, Any]:
        """Serialize for shared/state_machine.json (Fast Loop reads this)."""
        return {
            "n_states": self.n_states,
            "medoids_hex": [m.hex() for m in self.medoids],
            "features": self.features,
            "transitions": {
                f"{i}->{j}": p for (i, j), p in self.transitions.items()
            },
            "cluster_diameters": self.cluster_diameters,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProbabilisticStateMachine":
        """Deserialize from shared/state_machine.json."""
        medoids = [bytes.fromhex(h) for h in d.get("medoids_hex", [])]
        features = [list(f) for f in d.get("features", [])]
        transitions = {}
        for k, v in d.get("transitions", {}).items():
            parts = k.split("->")
            if len(parts) == 2:
                transitions[(int(parts[0]), int(parts[1]))] = float(v)
        diameters = list(d.get("cluster_diameters", []))
        return cls(
            medoids=medoids,
            features=features,
            transitions=transitions,
            cluster_diameters=diameters,
            n_states=d.get("n_states", len(medoids)),
        )

    def to_hint(self) -> str:
        """Text summary for LLM prompt — state machine overview."""
        if not self.medoids:
            return ""
        lines = [f"Inferred protocol state machine ({self.n_states} states):"]
        for i, m in enumerate(self.medoids):
            ascii_preview = m[:16].decode("ascii", errors="replace").strip()
            lines.append(f"  State {i}: header='{ascii_preview}' (hex={m[:8].hex()}...)")
        # Top transitions
        sorted_t = sorted(self.transitions.items(), key=lambda x: -x[1])[:10]
        for (si, sj), p in sorted_t:
            lines.append(f"  {si} -> {sj} (p={p:.2f})")
        return "\n".join(lines)


# ===========================================================================
# Feature extraction & similarity (Veritas §3.2)
# ===========================================================================


def _byte_frequency_vector(data: bytes) -> list[int]:
    """256-dim vector: count of each byte value (0x00–0xFF) in data."""
    vec = [0] * 256
    for b in data:
        vec[b] += 1
    return vec


def _jaccard_index(a: list[int], b: list[int]) -> float:
    """Jaccard similarity between two byte-frequency feature vectors.

    Interpreted as SETS: a byte value is "present" if its count > 0.
    J = |A ∩ B| / |A ∪ B|, where A = {byte values with count > 0}.
    """
    set_a = {i for i, c in enumerate(a) if c > 0}
    set_b = {i for i, c in enumerate(b) if c > 0}
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def _jaccard_distance(a: list[int], b: list[int]) -> float:
    """1 - Jaccard index (the distance metric for PAM clustering)."""
    return 1.0 - _jaccard_index(a, b)


# ===========================================================================
# Step 1: Message format extraction (Veritas §3.1)
# ===========================================================================

_MESSAGE_UNIT_LEN = 3  # Veritas: 3-byte subsequences
_HEADER_BYTES = 12     # Veritas: first n bytes of each packet


def _extract_message_units(packets: list[bytes]) -> Counter:
    """Extract all 3-byte units from the first 12 bytes of each packet.

    Returns a Counter of unit_bytes → frequency.
    """
    units: Counter = Counter()
    for pkt in packets:
        header = pkt[:_HEADER_BYTES]
        for i in range(len(header) - _MESSAGE_UNIT_LEN + 1):
            unit = header[i : i + _MESSAGE_UNIT_LEN]
            units[unit] += 1
    return units


def _two_sample_ks_test(freq_a: dict, freq_b: dict, alpha: float = 1e-8) -> bool:
    """Two-sample Kolmogorov-Smirnov test (pure Python, no scipy).

    Tests whether two empirical frequency distributions are drawn from the
    same underlying distribution. Returns True if H0 (same distribution)
    is accepted at significance level alpha.

    The K-S statistic D = max|F_A(x) - F_B(x)| over the empirical CDFs.
    H0 is rejected if sqrt(n_a*n_b/(n_a+n_b)) * D > K_alpha, where
    K_alpha satisfies Pr(K <= K_alpha) = 1 - alpha under the Kolmogorov
    distribution. For alpha = 1e-8, K_alpha ≈ 3.08 (from 2*e^(-2x^2) = alpha).
    """
    import math
    n_a = sum(freq_a.values())
    n_b = sum(freq_b.values())
    if n_a == 0 or n_b == 0:
        return True
    # Sort all distinct values, compute empirical CDFs, find max D.
    all_vals = sorted(set(freq_a.keys()) | set(freq_b.keys()))
    cum_a = 0
    cum_b = 0
    d_max = 0.0
    for v in all_vals:
        cum_a += freq_a.get(v, 0)
        cum_b += freq_b.get(v, 0)
        d = abs(cum_a / n_a - cum_b / n_b)
        if d > d_max:
            d_max = d
    # Critical value: K_alpha / sqrt(n_eff)
    k_alpha = 3.08  # for alpha = 1e-8
    n_eff = n_a * n_b / (n_a + n_b)
    if n_eff == 0:
        return True
    d_critical = k_alpha / math.sqrt(n_eff)
    return d_max <= d_critical


def _ks_test_filter(units: Counter, packets: list[bytes],
                    alpha: float = 1e-8) -> set[bytes]:
    """Veritas K-S test filter: find the frequency threshold λ such that
    the two-sample K-S test on the unit frequency distributions of two
    random packet halves ACCEPTS H0 (same distribution).

    Units with frequency ≥ λ in BOTH halves are candidate protocol units.
    This retains only units whose frequency is statistically consistent
    (not random noise), per the Veritas algorithm.
    """
    if not units or len(packets) < 4:
        # Too few packets for splitting — fallback: simple frequency cut.
        return {u for u, f in units.items() if f >= 2}

    # Split packets into two halves (deterministic for reproducibility).
    half = len(packets) // 2
    pkt_a = packets[:half]
    pkt_b = packets[half:]

    # Count units in each half.
    freq_a: Counter = Counter()
    freq_b: Counter = Counter()
    for pkt in pkt_a:
        header = pkt[:_HEADER_BYTES]
        for i in range(len(header) - _MESSAGE_UNIT_LEN + 1):
            freq_a[header[i:i + _MESSAGE_UNIT_LEN]] += 1
    for pkt in pkt_b:
        header = pkt[:_HEADER_BYTES]
        for i in range(len(header) - _MESSAGE_UNIT_LEN + 1):
            freq_b[header[i:i + _MESSAGE_UNIT_LEN]] += 1

    # Progressive λ (Veritas): INCREASE from low to high until K-S accepts.
    # At low λ, noise units create divergent distributions → K-S rejects.
    # At high λ, only consistent protocol units remain → K-S accepts.
    all_freqs = sorted(set(freq_a.values()) | set(freq_b.values()))  # ascending
    best_lambda = max(all_freqs) if all_freqs else 1  # fallback: strictest
    for lam in all_freqs:
        filtered_a = {u: f for u, f in freq_a.items() if f >= lam}
        filtered_b = {u: f for u, f in freq_b.items() if f >= lam}
        if not filtered_a or not filtered_b:
            continue
        if _two_sample_ks_test(filtered_a, filtered_b, alpha):
            best_lambda = lam
            break

    # Candidate units: appear ≥ best_lambda in BOTH halves.
    return {u for u in units
            if freq_a.get(u, 0) >= best_lambda
            and freq_b.get(u, 0) >= best_lambda}


def _reconstruct_format_messages(
    packets: list[bytes], candidate_units: set[bytes]
) -> list[tuple[bytes, int]]:
    """Reconstruct protocol format messages from candidate units.

    For each packet, greedily extend from position 0 using candidate 3-byte
    units. Returns (format_msg, packet_index) pairs so the caller can build
    feature vectors from the ORIGINAL packet headers (not just the short
    format message), ensuring consistency between clustering and labeling.
    """
    results: list[tuple[bytes, int]] = []
    for idx, pkt in enumerate(packets):
        header = pkt[:_HEADER_BYTES]
        # Try starting from position 0 (Veritas: format messages start at the beginning)
        seq = b""
        i = 0
        while i <= len(header) - _MESSAGE_UNIT_LEN:
            unit = header[i : i + _MESSAGE_UNIT_LEN]
            if unit in candidate_units:
                seq += header[i : i + 1]
                i += 1
            else:
                break
        if len(seq) >= _MESSAGE_UNIT_LEN:
            results.append((header[:i], idx))
    return results


def _frequency_candidate_units(
    packets: list[bytes], min_packets: int = 2
) -> set[bytes]:
    """Frequency-based candidate units — a black-box fallback when the KS
    filter over-prunes on a small or unbalanced sample.

    A unit is a candidate if it appears in the header of at least
    ``min_packets`` distinct packets. Frequency is a protocol-agnostic
    structural signal (a real framing unit recurs; random noise does not),
    so this needs no protocol knowledge. We additionally boost units that
    appear at offset 0 of any packet, because format messages start at the
    beginning — a position prior, not a protocol-specific constant.
    """
    from collections import defaultdict
    per_packet: dict[bytes, set[int]] = defaultdict(set)
    for idx, pkt in enumerate(packets):
        header = pkt[:_HEADER_BYTES]
        seen: set[bytes] = set()
        for i in range(len(header) - _MESSAGE_UNIT_LEN + 1):
            unit = header[i : i + _MESSAGE_UNIT_LEN]
            if unit not in seen:  # count once per packet
                per_packet[unit].add(idx)
                seen.add(unit)
    candidates = {u for u, pkts in per_packet.items() if len(pkts) >= min_packets}
    # Position prior: always keep units that sit at offset 0 of ≥1 packet —
    # those are the only units the greedy reconstruct can start from.
    for pkt in packets:
        header = pkt[:_HEADER_BYTES]
        if len(header) >= _MESSAGE_UNIT_LEN:
            candidates.add(header[:_MESSAGE_UNIT_LEN])
    return candidates


# ===========================================================================
# Step 2: PAM clustering + Dunn index (Veritas §3.2)
# ===========================================================================


def _pam_cluster(
    features: list[list[int]], k: int
) -> tuple[list[int], list[list[int]]]:
    """Partitioning Around Medoids (PAM).

    Returns (medoid_indices, clusters) where clusters[i] = list of point
    indices assigned to medoid i.

    Simplified PAM: random init → swap-improve. Good enough for small datasets.
    """
    n = len(features)
    if n == 0 or k <= 0:
        return [], []
    k = min(k, n)

    # Pre-compute distance matrix
    dist = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            d = _jaccard_distance(features[i], features[j])
            dist[i][j] = d
            dist[j][i] = d

    # Init: pick k evenly-spaced medoids (deterministic, better than random)
    step = max(1, n // k)
    medoids = list(range(0, n, step))[:k]

    # PAM swap phase (1 iteration — enough for small datasets)
    improved = True
    iterations = 0
    while improved and iterations < 3:
        improved = False
        iterations += 1
        # Assign points to nearest medoid
        clusters = [[] for _ in range(k)]
        for j in range(n):
            nearest = min(range(k), key=lambda mi: dist[medoids[mi]][j])
            clusters[nearest].append(j)
        # Try swapping each medoid with each non-medoid.
        # Skip swap phase when k=1 — no alternative medoid to compare.
        if k < 2:
            break
        for mi in range(k):
            best_cost = sum(
                dist[medoids[mi]][j] for j in clusters[mi]
            )
            for h in range(n):
                if h in medoids:
                    continue
                new_cost = sum(
                    min(dist[h][j], min(
                        dist[medoids[other]][j]
                        for other in range(k) if other != mi
                    ))
                    for j in range(n)
                )
                old_cost = sum(
                    min(dist[medoids[mi]][j], min(
                        dist[medoids[other]][j]
                        for other in range(k) if other != mi
                    ))
                    for j in range(n)
                )
                if new_cost < old_cost:
                    medoids[mi] = h
                    improved = True
                    break

    # Final assignment
    clusters = [[] for _ in range(k)]
    for j in range(n):
        nearest = min(range(k), key=lambda mi: dist[medoids[mi]][j])
        clusters[nearest].append(j)
    return medoids, clusters


def _dunn_index(
    features: list[list[int]], medoids: list[int], clusters: list[list[int]]
) -> float:
    """Dunn index: min inter-cluster distance / max intra-cluster diameter."""
    k = len(medoids)
    if k < 2:
        return 0.0
    # Inter-cluster distances (between medoids)
    min_inter = float("inf")
    for i in range(k):
        for j in range(i + 1, k):
            d = _jaccard_distance(features[medoids[i]], features[medoids[j]])
            if d < min_inter:
                min_inter = d
    # Intra-cluster diameters
    max_diameter = 0.0
    for ci in range(k):
        if len(clusters[ci]) < 2:
            continue
        for a in range(len(clusters[ci])):
            for b in range(a + 1, len(clusters[ci])):
                d = _jaccard_distance(
                    features[clusters[ci][a]], features[clusters[ci][b]]
                )
                if d > max_diameter:
                    max_diameter = d
    if max_diameter == 0:
        return min_inter if min_inter != float("inf") else 0.0
    return min_inter / max_diameter


def _optimal_k(features: list[list[int]], max_k: int = 12) -> int:
    """Find k that maximizes Dunn index."""
    n = len(features)
    if n < 4:
        return min(n, 2)
    max_k = min(max_k, n)
    best_k = 2
    best_dunn = -1.0
    for k in range(2, max_k + 1):
        medoids, clusters = _pam_cluster(features, k)
        dunn = _dunn_index(features, medoids, clusters)
        if dunn > best_dunn:
            best_dunn = dunn
            best_k = k
    return best_k


# ===========================================================================
# Step 4: State machine inference (Veritas §3.4)
# ===========================================================================


def _infer_transitions(
    sessions: list[list[int]],
    n_states: int,
) -> dict[tuple[int, int], float]:
    """Build transition probability matrix from labeled sessions.

    Each session is a list of state indices. Count consecutive pairs, normalize.

    Veritas §3.4: "only keeps the state type pairs with a frequency above
    0.005" — filters noise transitions (e.g. single-occurrence mislabeled
    pairs from out-of-order packets or Jaccard mislabeling).
    """
    pair_counts: Counter = Counter()
    state_counts: Counter = Counter()
    for sess in sessions:
        for i in range(len(sess) - 1):
            pair_counts[(sess[i], sess[i + 1])] += 1
            state_counts[sess[i]] += 1
    total_pairs = sum(pair_counts.values())
    transitions: dict[tuple[int, int], float] = {}
    for (si, sj), count in pair_counts.items():
        # Veritas frequency threshold: filter noise transitions.
        if total_pairs > 0 and count / total_pairs < 0.005:
            continue
        total = state_counts.get(si, 1)
        if total > 0:
            transitions[(si, sj)] = count / total
    return transitions


def _cluster_diameters(
    features: list[list[int]], clusters: list[list[int]]
) -> list[float]:
    """Max intra-cluster distance for each cluster."""
    diameters = []
    for ci in clusters:
        if len(ci) < 2:
            diameters.append(0.0)
            continue
        max_d = 0.0
        for a in range(len(ci)):
            for b in range(a + 1, len(ci)):
                d = _jaccard_distance(features[ci[a]], features[ci[b]])
                if d > max_d:
                    max_d = d
        diameters.append(max_d)
    return diameters


# ===========================================================================
# StateMachineInferer — main entry point
# ===========================================================================


class StateMachineInferer:
    """Veritas-inspired P-PSM inference from network traces.

    Pure black-box: infers state machine from captured traffic WITHOUT any
    protocol specification, source code, or hardcoded keywords. Works on
    both text and binary protocols.

    Usage:
        inferer = StateMachineInferer()
        psm = inferer.infer(packets, sessions)
        state_idx = psm.label_packet(response_bytes)
    """

    def __init__(self, min_packets: int = 10) -> None:
        self.min_packets = min_packets

    def infer(
        self,
        packets: list[bytes],
        sessions: Optional[list[list[bytes]]] = None,
    ) -> ProbabilisticStateMachine:
        """Infer a P-PSM from captured traffic.

        Args:
            packets:  all captured packets (both directions, raw bytes).
            sessions: optional list of sessions, each a list of packets in order.
                      Used for transition inference. If None, uses packets in order.

        Returns:
            A ProbabilisticStateMachine (P-PSM).
        """
        if len(packets) < self.min_packets:
            log.debug(
                f"StateMachineInferer: {len(packets)} packets < min "
                f"{self.min_packets}, skipping inference"
            )
            return ProbabilisticStateMachine()

        log.info(f"StateMachineInferer: inferring P-PSM from {len(packets)} packets")

        # Step 1: Message format extraction
        units = _extract_message_units(packets)
        candidate_units = _ks_test_filter(units, packets)
        fmt_results = _reconstruct_format_messages(packets, candidate_units)
        fmt_source = "ks"
        if len(fmt_results) < 3:
            # Frequency fallback. The KS filter (Veritas) can over-prune on a
            # small / unbalanced sample: the protocol units that sit at offset
            # 0 (where format messages start) get dropped as "unbalanced"
            # between the two packet halves, so the greedy reconstruct cannot
            # even begin and yields < 3. Frequency is a protocol-agnostic
            # structural signal; combined with an offset-0 prior it recovers
            # those start units. Used only when KS under-produces, never
            # replacing KS on healthy samples.
            for _min_pkts in (2, 1):
                cand = _frequency_candidate_units(packets, min_packets=_min_pkts)
                fmt_results = _reconstruct_format_messages(packets, cand)
                if len(fmt_results) >= 3:
                    fmt_source = f"frequency-fallback(min_pkts={_min_pkts})"
                    break
        if len(fmt_results) < 3:
            log.debug(
                "StateMachineInferer: too few format messages after KS + "
                "frequency fallback, skipping"
            )
            return ProbabilisticStateMachine()
        if fmt_source != "ks":
            log.info(
                f"StateMachineInferer: KS filter under-produced format "
                f"messages; inferred via {fmt_source} "
                f"({len(fmt_results)} format messages)"
            )

        # Step 2: Feature extraction from ORIGINAL packet headers (12B),
        # NOT from short format messages. This ensures label_packet() —
        # which also uses packet[:12] — produces consistent Jaccard distances.
        # Using format_msg features (3-4 bytes) vs packet[:12] (12 bytes)
        # inflates distances (0.7+ for matching commands) → wrong labeling.
        format_msgs = [fm for fm, _ in fmt_results]
        packet_indices = [idx for _, idx in fmt_results]
        features = [_byte_frequency_vector(packets[idx][:_HEADER_BYTES])
                     for idx in packet_indices]
        k = _optimal_k(features, max_k=min(12, len(features)))
        if k < 2:
            log.debug("StateMachineInferer: optimal k < 2, skipping")
            return ProbabilisticStateMachine()

        medoid_indices, clusters = _pam_cluster(features, k)
        medoids = [format_msgs[mi] for mi in medoid_indices]
        medoid_features = [features[mi] for mi in medoid_indices]
        diameters = _cluster_diameters(features, clusters)

        log.info(
            f"StateMachineInferer: {k} states inferred, "
            f"top transitions being computed..."
        )

        # Step 3+4: Label sessions + infer transitions
        # Use global d_max capped at 0.75 (consistent with label_packet).
        global_d_max = 2 * max(diameters) if diameters else 0.5
        global_d_max = min(global_d_max, 0.75)
        if global_d_max == 0:
            global_d_max = 0.5
        labeled_sessions: list[list[int]] = []
        if sessions:
            for sess in sessions:
                labels = []
                for pkt in sess:
                    feat = _byte_frequency_vector(pkt[:_HEADER_BYTES])
                    best_idx = -1
                    best_dist = float("inf")
                    for mi_idx, mf in enumerate(medoid_features):
                        d = _jaccard_distance(feat, mf)
                        if d < best_dist:
                            best_dist = d
                            best_idx = mi_idx
                    if best_idx >= 0 and best_dist <= global_d_max:
                        labels.append(best_idx)
                if len(labels) >= 2:
                    labeled_sessions.append(labels)

        transitions = _infer_transitions(labeled_sessions, k)

        psm = ProbabilisticStateMachine(
            medoids=medoids,
            features=medoid_features,
            transitions=transitions,
            cluster_diameters=diameters,
            n_states=k,
        )
        log.info(
            f"StateMachineInferer: P-PSM with {k} states, "
            f"{len(transitions)} transitions inferred"
        )
        return psm
