# LIFA-Fuzz — Adaptive State Sampling: Implementation Plan
## "Continuous Adaptive State Sampling" via EWMA Controller

**Nhóm bài toán:** Group 3 — I/O Bottleneck vs. State Blindness  
**Phiên bản:** v1.0  
**Trạng thái:** Ready for implementation  

---

## 1. Bối cảnh & Vấn đề

### 1.1 Dilemma hiện tại

```
Fast Loop (400+ EPS)          Slow Loop (LLM Brain)
┌─────────────────────┐       ┌──────────────────────┐
│ no_recv = True      │  ←X→  │ Coverage Analysis    │
│ Fire-and-forget     │       │ Protocol Inference   │
│ Throughput-first    │       │ Rule Generation      │
└─────────────────────┘       └──────────────────────┘
        ↑                              ↑
   "MUSCLE": mù về state        "BRAIN": không điều
   server, không biết           phối được tốc độ
   server đang phản ứng gì      của Muscle
```

**Hai extreme đều sai:**
- `no_recv = True` mãi mãi: EPS cao nhưng **state blind** — không biết server đang reject, crash, hay thay đổi hành vi.
- `no_recv = False` mãi mãi: EPS giảm từ 400+ xuống 40-80 (bottleneck tại `recv()` timeout).

### 1.2 Tại sao AIMD reset cứng không đủ tốt

Theo phân tích toán học (Document 4), luật AIMD piecewise:

$$k_{t+1} = \begin{cases} 1 & \text{nếu } \Delta C_t > 0 \\ \min(k_t + \alpha, K_{\max}) & \text{nếu } \Delta C_t = 0 \end{cases}$$

có ba điểm yếu chính:

| Vấn đề | Hệ quả trong fuzzing |
|--------|---------------------|
| **Chattering**: reset k=1 khi bất kỳ ΔC>0 | Micro-burst coverage liên tục oscillate k giữa 1 và K_max |
| **Không có hysteresis** | Hệ thống phản ứng noise Poisson thay vì xu hướng thực |
| **Không xét magnitude** | 1 path mới = 50 path mới → xử lý như nhau |

### 1.3 Giải pháp: Formula liên tục EWMA

Từ phân tích Lyapunov (Document 4), formula tối ưu là:

$$k(t) = \left\lfloor \frac{K_{\max}}{1 + \theta \cdot \lambda_C(t)} \right\rfloor$$

trong đó $\lambda_C(t)$ là **coverage intensity** ước lượng bằng EWMA:

$$\lambda_C(t) = \delta \cdot \Delta C_t + (1 - \delta) \cdot \lambda_C(t-1)$$

**Tại sao formula này đúng về mặt toán học:**
- **Liên tục & differentiable**: không có discontinuity → không chattering.
- **Hysteresis tự nhiên**: EWMA smooth hoá → $\lambda_C$ không nhảy cóc theo từng event.
- **Xét magnitude**: $\Delta C_t = 50$ làm $\lambda_C$ tăng mạnh hơn $\Delta C_t = 1$ → k giảm sâu hơn.
- **Stochastic Approximation** (Robbins-Monro): EWMA là estimator online của Poisson intensity → convergence đảm bảo.
- **Ultimately bounded** theo Lyapunov: hệ thống hội tụ về ball quanh $k^*$ thay vì oscillate vô hạn.

---

## 2. Kiến trúc Tổng thể

```
┌──────────────────────────────────────────────────────────────────┐
│                    SHARED STATE (IPC Layer)                      │
│         multiprocessing.Value('i', 200)  ←  current_k           │
│         ┌─────────────────────────────────────┐                  │
│         │   Zero-overhead: mmap backed,        │                  │
│         │   atomic 32-bit int read/write       │                  │
│         └─────────────────────────────────────┘                  │
└────────────────────────┬─────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          │ WRITE (Slow Loop)           │ READ (Fast Loop)
          ↓                            ↓
┌─────────────────────┐    ┌──────────────────────────────┐
│   SLOW LOOP         │    │   FAST LOOP                  │
│   (EWMA Brain)      │    │   (Adaptive Muscle)          │
│                     │    │                              │
│ Per epoch:          │    │ Per batch (every 50 packets):│
│  1. Get delta_C     │    │  1. Read current_k (non-blk) │
│  2. Update lambda_c │    │  2. packet_counter++         │
│  3. Compute k       │    │  3. Send packet              │
│  4. Write to IPC    │    │  4. if counter % k == 0:     │
│                     │    │       recv() → log state     │
└─────────────────────┘    └──────────────────────────────┘
```

### 2.1 Hành vi theo coverage state

| Tình huống | ΔC_t | λ_c sau EWMA | k | Hành vi Fast Loop |
|-----------|------|-------------|---|------------------|
| Protocol mới, nhiều state mới | 20 | 0.20→1.2 | 24 | recv() mỗi 24 gói — theo dõi sát |
| Fuzzing bình thường | 3 | 0.03→0.2 | 83 | recv() mỗi 83 gói — cân bằng |
| Coverage bão hoà | 0 | decay → 0 | 200 | recv() mỗi 200 gói — gần như fire-and-forget |
| Crash phát hiện | spike | high | ~10 | recv() rất thường — tối đa state info |

---

## 3. Thông số Hệ thống

### 3.1 Constants (đặt trong config.yaml)

```yaml
# fast_loop/adaptive_sampling:
ewma:
  delta: 0.1          # Smoothing factor — EWMA weight cho delta_C mới
                      # Lớn hơn = phản ứng nhanh hơn, ít smooth hơn
                      # Nhỏ hơn = smooth hơn, chậm thích nghi hơn
                      # Khuyến nghị: 0.05 ≤ δ ≤ 0.2
  K_max: 200          # Sampling interval tối đa (fire-and-forget ceiling)
                      # = EPS mục tiêu tối đa / EPS khi recv() mỗi gói
  theta: 5.0          # Sensitivity gain — điều chỉnh độ dốc của phản ứng
                      # Lớn hơn = k giảm nhanh khi coverage tăng
                      # Nhỏ hơn = hệ thống ít nhạy cảm hơn
  k_min: 1            # Sampling interval tối thiểu (recv() mỗi gói)
  ipc_read_interval: 50  # Đọc current_k từ IPC mỗi N packets (tránh overhead)
```

### 3.2 Giải thích tham số θ (theta)

Tại coverage intensity $\lambda_C = 0.2$:
- θ=5: k = 200/(1+1.0) = **100** (recv() mỗi 100 gói)
- θ=10: k = 200/(1+2.0) = **67** (recv() mỗi 67 gói)
- θ=2: k = 200/(1+0.4) = **143** (recv() mỗi 143 gói)

→ Tăng θ khi muốn hệ thống phản ứng mạnh hơn với coverage signal.

---

## 4. Task 1 — IPC Layer (Shared Memory)

### 4.1 File: `shared/adaptive_state.py` (TẠO MỚI)

**Nguyên tắc thiết kế:**
- Sử dụng `multiprocessing.Value('i', 200)` — atomic 32-bit integer.
- Python GIL không bảo vệ multiprocessing Value → dùng `.get_lock()` **chỉ khi write**.
- Fast Loop đọc **không cần lock** (torn read trên 32-bit int là an toàn trên x86/ARM).
- Tuyệt đối không dùng Queue, Pipe, hoặc socket cho IPC này — overhead quá lớn.

**Pseudocode:**

```python
# shared/adaptive_state.py
import ctypes
from multiprocessing import Value
from multiprocessing.sharedctypes import Synchronized

class AdaptiveSamplingState:
    """
    Zero-overhead shared state between Fast Loop and Slow Loop.
    
    EWMA Adaptive Controller IPC:
    - Writer: Slow Loop (EWMA brain) — updates current_k each epoch
    - Reader: Fast Loop (Adaptive Muscle) — reads current_k each batch
    
    Implementation: multiprocessing.Value backed by mmap.
    Read is lock-free (safe for 32-bit atomic on x86/ARM64).
    Write acquires lock briefly (<1µs) to prevent torn writes.
    """
    
    def __init__(self, K_max: int = 200):
        # Shared 32-bit signed int, mmap-backed (zero IPC overhead on read)
        self._current_k: Synchronized = Value(ctypes.c_int, K_max)
        self._K_max = K_max
    
    def read_k(self) -> int:
        """
        Lock-free read — called by Fast Loop every N packets.
        Safe: 32-bit int reads are atomic on x86_64 and ARM64.
        """
        return self._current_k.value  # no lock needed on 32-bit aligned int
    
    def write_k(self, k: int) -> None:
        """
        Locked write — called by Slow Loop each EWMA epoch (~1-10s).
        Lock held <1µs → negligible impact on Fast Loop.
        """
        clamped = max(1, min(self._K_max, int(k)))
        with self._current_k.get_lock():
            self._current_k.value = clamped
    
    @property
    def K_max(self) -> int:
        return self._K_max
```

**Integration point:**
- Khởi tạo `AdaptiveSamplingState` trong orchestrator/main.py TRƯỚC khi spawn processes.
- Pass instance vào cả Slow Loop process và Fast Loop process qua argument.
- `multiprocessing.Value` tự động share qua fork — không cần serialize.

---

## 5. Task 2 — EWMA Controller (Slow Loop)

### 5.1 Vị trí trong codebase

Tìm và locate các điểm sau trong Slow Loop:
1. Nơi Slow Loop nhận TrafficLog từ Interceptor → đây là epoch boundary.
2. Nơi coverage được đếm (số path mới, số unique response pattern, số state mới).
3. Nơi SemanticRuleSet được update và push về Fast Loop.

### 5.2 File: `slow_loop/ewma_controller.py` (TẠO MỚI)

**Pseudocode hoàn chỉnh:**

```python
# slow_loop/ewma_controller.py
import math
from shared.adaptive_state import AdaptiveSamplingState
from shared.logger import get_logger

log = get_logger("slow_loop.ewma_controller")

class EWMAController:
    """
    EWMA Adaptive Controller — điều phối Fast Loop sampling interval.
    
    Mathematical model (Document 4, Section 3):
        λ_C(t) = δ·ΔC_t + (1-δ)·λ_C(t-1)       [EWMA coverage intensity]
        k(t)   = floor(K_max / (1 + θ·λ_C(t)))   [Adaptive sampling interval]
    
    Properties:
        - Continuous & differentiable → no chattering
        - Built-in hysteresis via EWMA smoothing
        - Magnitude-aware: ΔC=50 reduces k more than ΔC=1
        - Lyapunov-stable: ultimately bounded around optimal k*
    
    Tuning:
        delta  ∈ [0.05, 0.20] — smoothing factor
        theta  ∈ [2, 15]      — sensitivity gain
        K_max  = target max EPS / EPS when always recv()
    """
    
    def __init__(
        self,
        shared_state: AdaptiveSamplingState,
        delta: float = 0.1,
        theta: float = 5.0,
        K_max: int   = 200,
        k_min: int   = 1,
    ):
        self.shared  = shared_state
        self.delta   = delta       # EWMA smoothing factor
        self.theta   = theta       # Sensitivity gain
        self.K_max   = K_max       # Max sampling interval (fire-and-forget)
        self.k_min   = k_min       # Min sampling interval (always recv)
        
        # EWMA state — persists across epochs
        self._lambda_c: float = 0.0  # Coverage intensity estimate
        self._prev_coverage_total: int = 0
        
        log.info("EWMAController initialized", extra={"context": {
            "delta": delta, "theta": theta, "K_max": K_max
        }})
    
    def update(self, current_coverage_total: int) -> int:
        """
        Called once per Slow Loop analysis epoch.
        
        Args:
            current_coverage_total: Tổng số coverage paths/states hiện tại.
                                    Slow Loop tự tính từ response analysis.
        
        Returns:
            current_k: Giá trị k mới đã được ghi vào shared memory.
        """
        # Step 1: Compute delta_C (new coverage this epoch)
        delta_C = max(0, current_coverage_total - self._prev_coverage_total)
        self._prev_coverage_total = current_coverage_total
        
        # Step 2: EWMA update — Stochastic Approximation (Robbins-Monro)
        # λ_C(t) = δ·ΔC_t + (1-δ)·λ_C(t-1)
        self._lambda_c = (self.delta * delta_C) + ((1 - self.delta) * self._lambda_c)
        
        # Step 3: Compute new k — continuous formula (no hard reset)
        # k(t) = floor(K_max / (1 + θ·λ_C(t)))
        k_raw   = self.K_max / (1.0 + self.theta * self._lambda_c)
        k_new   = max(self.k_min, math.floor(k_raw))
        
        # Step 4: Write to IPC shared memory (locked write, <1µs)
        self.shared.write_k(k_new)
        
        log.info(
            "EWMA Adaptive Controller update",
            extra={"context": {
                "delta_C":   delta_C,
                "lambda_c":  f"{self._lambda_c:.4f}",
                "k_new":     k_new,
                "k_raw":     f"{k_raw:.2f}",
                "regime":    self._classify_regime(k_new),
            }},
        )
        
        return k_new
    
    def _classify_regime(self, k: int) -> str:
        """Human-readable regime label for logging."""
        ratio = k / self.K_max
        if ratio <= 0.1:   return "INTENSIVE (high coverage)"
        if ratio <= 0.33:  return "ACTIVE (moderate coverage)"
        if ratio <= 0.66:  return "NORMAL (low coverage)"
        return "SPARSE (coverage saturated)"
    
    @property
    def lambda_c(self) -> float:
        """Current coverage intensity estimate (for telemetry)."""
        return self._lambda_c
```

### 5.3 Integration trong Slow Loop

**Vị trí gọi `controller.update()`:**

```python
# slow_loop/orchestrator.py (hoặc nơi Slow Loop xử lý TrafficLog)
# Tìm hàm/method xử lý sau mỗi batch analysis epoch

# Sau khi analysis_result được tính xong:
new_coverage_count = len(analysis_result.unique_response_patterns)
#                       └── hoặc: unique state transitions, unique paths, etc.
#                           Bất kỳ metric nào đo "số state mới phát hiện"

controller.update(current_coverage_total=new_coverage_count)
# → Tự động ghi current_k mới vào IPC
```

**Nếu Slow Loop không có coverage metric sẵn:**  
Dùng số unique response lengths hoặc số unique response hex prefixes (8 bytes đầu) làm proxy coverage.

---

## 6. Task 3 — Adaptive Sampling (Fast Loop)

### 6.1 Vị trí trong codebase

Tìm trong `fast_loop/mutator.py`:
- Method `_send()` (line ~700-761): đây là nơi gọi `recv()` hoặc không.
- Method `run()` (line ~390-438): hot loop.
- Biến `no_recv` (line ~295): cờ hiện tại.

### 6.2 Thay đổi trong `fast_loop/mutator.py`

**Thêm vào `MutationEngine.__init__()`:**

```python
# Thêm parameter mới:
def __init__(
    self,
    ...
    adaptive_state: Optional[AdaptiveSamplingState] = None,  # EWMA IPC handle
    ipc_read_interval: int = 50,                              # Read k every N packets
    ...
):
    ...
    # EWMA Adaptive Controller state
    self._adaptive_state   = adaptive_state
    self._ipc_read_interval = ipc_read_interval
    self._current_k: int   = adaptive_state.read_k() if adaptive_state else (1 if not no_recv else 200)
    self._packet_counter: int = 0   # Global send counter (không reset)
    self._recv_count: int    = 0    # Số lần thực sự gọi recv() (cho telemetry)
```

**Thay đổi `_send()` method:**

```python
async def _send(self, payload: bytes, seed_id: str) -> PacketStatus:
    """
    Adaptive State Sampling send — EWMA Adaptive Controller.
    
    Sampling logic:
        - Every K packets: call recv() (sample server state)
        - Other packets:   fire-and-forget (maintain max throughput)
    
    K is controlled by Slow Loop EWMA brain via shared memory.
    K=1   → always recv (intensive monitoring, low EPS)
    K=200 → recv every 200 packets (fire-and-forget dominant, high EPS)
    """
    self._packet_counter += 1
    
    # ── Read current_k from IPC (non-blocking, every ipc_read_interval sends)
    # EWMA Adaptive Controller: refresh k without blocking the hot loop
    if self._adaptive_state and (self._packet_counter % self._ipc_read_interval == 0):
        self._current_k = self._adaptive_state.read_k()  # lock-free read
    
    # ── Decide: sample this packet or fire-and-forget?
    # EWMA Adaptive Controller: sample every current_k-th packet
    should_recv = (self._packet_counter % self._current_k == 0)
    
    status = PacketStatus.TIMEOUT
    
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.target_host, self.target_port),
            timeout=self.connection_timeout,
        )
        
        writer.write(payload)
        await writer.drain()
        
        if should_recv:
            # ── SAMPLING TICK: recv() to observe server state
            # EWMA Adaptive Controller: this is a "state sample" event
            self._recv_count += 1
            try:
                resp = await asyncio.wait_for(
                    reader.read(4096), timeout=self.recv_timeout
                )
                status = PacketStatus.ACCEPTED if resp else PacketStatus.REJECTED
            except asyncio.TimeoutError:
                status = PacketStatus.TIMEOUT
        else:
            # ── NON-SAMPLING TICK: fire-and-forget for maximum EPS
            # EWMA Adaptive Controller: skip recv() to maintain throughput
            status = PacketStatus.ACCEPTED  # optimistically assume OK
        
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    
    except ConnectionRefusedError:
        status = PacketStatus.CRASH
        ...  # existing crash handling unchanged
    
    ...  # existing error handling unchanged
    
    return status
```

### 6.3 Telemetry additions

**Thêm vào `MutatorStats`:**

```python
@dataclass
class MutatorStats:
    ...  # existing fields
    current_k:       int   = 200   # EWMA Adaptive Controller current interval
    recv_rate:        float = 0.0  # Fraction of sends that called recv()
    lambda_c_estimate: float = 0.0 # Coverage intensity (from Slow Loop via IPC)
```

**Thêm vào heartbeat log:**

```python
log.info("Fuzzing heartbeat", extra={"context": {
    ...  # existing fields
    "k":            self._current_k,                # EWMA sampling interval
    "recv_rate":    f"{self._recv_count/max(1,self._stats.total_sent):.1%}",
    "regime":       "intensive" if self._current_k < 20 else "normal" if self._current_k < 100 else "sparse",
}})
```

---

## 7. Sơ đồ Luồng Dữ liệu Hoàn chỉnh

```
Slow Loop Analysis Epoch
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  EWMAController.update(coverage_total)               │
│                                                     │
│  1. delta_C = coverage_total - prev_total           │
│  2. λ_C = δ·delta_C + (1-δ)·λ_C    [EWMA update]  │
│  3. k = floor(K_max / (1 + θ·λ_C)) [Formula]      │
│  4. shared_state.write_k(k)         [IPC write]    │
└─────────────────────────────────────────────────────┘
        │
        │  mmap-backed 32-bit atomic write (~100ns)
        ▼
┌─────────────────────────────────────────────────────┐
│  AdaptiveSamplingState._current_k = k               │
│  (multiprocessing.Value — shared across fork)       │
└─────────────────────────────────────────────────────┘
        │
        │  lock-free 32-bit read every 50 packets (~5ns)
        ▼
Fast Loop Hot Loop
        │
        ├── packet_counter++
        ├── if counter % 50 == 0: self._current_k = shared.read_k()
        ├── Send packet (always)
        └── if counter % current_k == 0:
                recv() → log state → PacketStatus.ACCEPTED/REJECTED
            else:
                skip recv() → PacketStatus.ACCEPTED (optimistic)
```

---

## 8. Kế hoạch Triển khai

### 8.1 Thứ tự implementation

```
Phase 1 (Day 1) — IPC Layer:
  [x] Tạo shared/adaptive_state.py
  [x] Unit test AdaptiveSamplingState (read/write từ 2 threads)
  [x] Verify no lock contention khi read từ Fast Loop thread

Phase 2 (Day 1-2) — EWMA Controller:
  [x] Tạo slow_loop/ewma_controller.py
  [x] Unit test với synthetic delta_C sequences:
      - Constant delta_C=10: k phải converge về ~29
      - delta_C=0 mãi mãi: k phải decay về K_max=200
      - Spike delta_C=50 rồi về 0: k spike xuống rồi recover
  [x] Integrate vào Slow Loop orchestrator

Phase 3 (Day 2) — Fast Loop Adaptive Sampling:
  [x] Sửa mutator.py: thêm packet_counter, should_recv logic
  [x] Backward compat: nếu adaptive_state=None, dùng no_recv cũ
  [x] Verify không thay đổi PacketStatus.CRASH detection

Phase 4 (Day 3) — Integration & Verification:
  [x] End-to-end test với sandbox target
  [x] Đo EPS baseline vs EPS với EWMA controller
  [x] Đo coverage improvement so với no_recv=True thuần túy
```

### 8.2 Backward compatibility

Để không break existing code:

```python
# Nếu không pass adaptive_state → hành vi cũ (no_recv flag)
engine = MutationEngine(
    ...
    adaptive_state=None,  # default — sử dụng no_recv cũ
    no_recv=True,         # backward compat
)

# EWMA mode:
adaptive_state = AdaptiveSamplingState(K_max=200)
engine = MutationEngine(
    ...
    adaptive_state=adaptive_state,
    # no_recv bị ignore khi adaptive_state không phải None
)
```

---

## 9. Verification Requirements

### 9.1 Performance verification (CRITICAL)

```python
# Chạy benchmark sau khi implement:
# tests/bench_adaptive_sampling.py

Configurations:
  A) no_recv=True (old): target baseline 400+ EPS
  B) adaptive k=200 (EWMA converged): target ≥ 380 EPS (≤5% overhead)
  C) adaptive k=10 (high coverage): target ~40-60 EPS (expected)

Verify: config B overhead so với A < 5%
Verify: config C EPS scales linearly với 1/k
```

### 9.2 Correctness verification

```python
# Verify EWMA formula implementation:
ctrl = EWMAController(shared, delta=0.1, theta=5, K_max=200)

# Test 1: Cold start (lambda_c=0) → k=K_max
ctrl.update(0)
assert ctrl.shared.read_k() == 200

# Test 2: High coverage → k giảm mạnh
ctrl.update(100)  # delta_C=100
lambda_expected = 0.1 * 100 + 0.9 * 0.0  # = 10.0
k_expected = floor(200 / (1 + 5*10.0)) = floor(200/51) = 3
assert ctrl.shared.read_k() == 3

# Test 3: Coverage decay → k recover về K_max
for _ in range(50):
    ctrl.update(0)  # delta_C=0 liên tục
# Sau 50 epochs không có coverage: lambda_c ≈ 10 * (0.9^50) ≈ 0.005
# k ≈ floor(200 / (1 + 5*0.005)) = floor(200/1.025) = 195
assert ctrl.shared.read_k() >= 190
```

### 9.3 IPC overhead verification

```python
# Measure IPC read overhead:
import timeit
state = AdaptiveSamplingState()
state.write_k(100)

# Lock-free read should be < 100ns
read_time = timeit.timeit(state.read_k, number=100_000) / 100_000
assert read_time < 100e-9, f"IPC read too slow: {read_time*1e9:.1f}ns"
```

---

## 10. Rủi ro & Mitigation

| Rủi ro | Xác suất | Impact | Mitigation |
|--------|----------|--------|-----------|
| IPC lock contention làm chậm Fast Loop | Thấp | Cao | Lock chỉ khi write; read là lock-free |
| Coverage metric Slow Loop không chính xác → sai λ_C | Trung bình | Trung bình | Dùng proxy metric (response length diversity) nếu cần |
| k=1 kéo dài → EPS crash xuống 0 | Thấp | Cao | k_min=1 luôn được enforce; k=1 chỉ khi λ_C cực kỳ cao |
| Process fork không share Value đúng cách | Thấp | Cao | Verify `multiprocessing.Value` được tạo TRƯỚC fork |
| Slow Loop chết → k không được update | Trung bình | Thấp | Fast Loop đọc last valid k; không có liveness dependency |

---

## 11. Files cần tạo/sửa

| Action | File | Nội dung |
|--------|------|---------|
| **TẠO MỚI** | `shared/adaptive_state.py` | IPC AdaptiveSamplingState class |
| **TẠO MỚI** | `slow_loop/ewma_controller.py` | EWMAController class |
| **SỬA** | `fast_loop/mutator.py` | Thêm packet_counter, adaptive recv logic |
| **SỬA** | `fast_loop/mutator.py` | Thêm `adaptive_state` param vào `__init__` |
| **SỬA** | `shared/schemas.py` | Thêm `current_k`, `recv_rate` vào MutatorStats |
| **SỬA** | `config.yaml` | Thêm `ewma` section |
| **TẠO MỚI** | `tests/test_ewma_controller.py` | Unit tests cho EWMA formula |
| **TẠO MỚI** | `tests/bench_adaptive_sampling.py` | EPS benchmark |