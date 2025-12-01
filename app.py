#!/usr/bin/env python3
"""

Monarch V10.5 — Agnostic Autonomy Safety Kernel (Graph-Driven, FSM Policy, Replay-
Deterministic)

Key invariants:
- Human-gated automation: kernel never talks to actuators directly
- Proposals -> human review/commit -> actuation intents
- DEMO mode can auto-commit non-safety-critical proposals (if allowed)
- SAFETY mode cannot auto-commit anything

V10.5 upgrades:
1) Episodic memory layer (deterministic, bounded)
2) FSM audit breadcrumbs
3) Hardened intent TTL enforcement with invalidation events
4) Risk explainability packets (per-feature contributions)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
import uuid

from abc import ABC, abstractmethod
from collections import deque
from copy import deepcopy
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple, Type

# ===================================================================
# Clock
# ===================================================================

class Clock(ABC):
@abstractmethod
def now(self) -> float:
...

@abstractmethod
def sleep(self, seconds: float) -> None:
...

class RealClock(Clock):
def now(self) -> float:
# Wall-clock time (seconds since epoch)
return time.time()

def sleep(self, s: float) -> None:
time.sleep(s)

# ===================================================================
# Config + Normalization
# ===================================================================

@dataclass(frozen=True)
class NormalizationProfile:
ranges: Dict[str, Tuple[float, float]]

def clamp_norm(self, key: str, value: float) -> float:
if key not in self.ranges:
raise ValueError(f"No normalization range for '{key}'")
lo, hi = self.ranges[key]
if hi <= lo:
raise ValueError(f"Invalid range for {key}: {lo}, {hi}")
x = (value - lo) / (hi - lo)
if x < 0.0:
return 0.0
if x > 1.0:
return 1.0
return x

@dataclass(frozen=True)
class RiskConfig:
weights: Dict[str, float]
thresholds: Dict[str, float]
policy_version: str
normalization: NormalizationProfile

def validate(self) -> None:
if not self.weights:
raise ValueError("Risk weights empty")
total = sum(self.weights.values())
if total <= 0:
raise ValueError("Risk weights must sum to > 0")
w, h, s = (self.thresholds[k] for k in ("watch", "hold", "stop"))
if not (0.0 <= w < h < s <= 1.0):
raise ValueError("Bad threshold ordering: watch < hold < stop")

def normalized_weights(self) -> Dict[str, float]:
total = sum(self.weights.values())
return {k: v / total for k, v in self.weights.items()}

@dataclass(frozen=True)
class SafetyConfig:

"""Hard safety invariants."""

allow_demo_mode: bool = True
allow_auto_commit_in_demo: bool = True
max_overbudget_streak: int = 3
fail_on_journal_tamper: bool = True
stop_proposal_cooling_ticks: int = 2

def validate(self, mode: str) -> None:
if mode not in ("DEMO", "SAFETY"):
raise ValueError(f"Unknown mode: {mode}")
# In SAFETY we don't *use* demo features, but we still validate settings
if mode == "SAFETY" and self.allow_auto_commit_in_demo:
# Not strictly illegal, but we won't auto-commit anyway.
return

def default_config() -> RiskConfig:
prof = NormalizationProfile(
ranges=dict(
speed_kph=(0, 140),
coolant_c=(40, 140),
lane_offset_m=(-3, 3),
obstacle_m=(0, 100),
)
)

cfg = RiskConfig(
weights={
"speed_norm": 0.25,
"temp_norm": 0.15,
"lateral_norm": 0.20,
"obstacle_norm": 0.25,
"comms_drop": 0.10,
"anomaly": 0.15,
},
thresholds=dict(
watch=0.30,
hold=0.55,
stop=0.80,
),
policy_version="10.5.0",
normalization=prof,
)
cfg.validate()
return cfg

def hash_config(cfg: RiskConfig, safety_cfg: SafetyConfig) -> str:
"""Hash of risk + safety config for attestation."""
blob = dict(
risk=dict(
weights=cfg.weights,

thresholds=cfg.thresholds,
policy_version=cfg.policy_version,
ranges=cfg.normalization.ranges,
),
safety=dict(
allow_demo_mode=safety_cfg.allow_demo_mode,
allow_auto_commit_in_demo=safety_cfg.allow_auto_commit_in_demo,
max_overbudget_streak=safety_cfg.max_overbudget_streak,
fail_on_journal_tamper=safety_cfg.fail_on_journal_tamper,
stop_proposal_cooling_ticks=safety_cfg.stop_proposal_cooling_ticks,
),
episodic_limits=dict(
terrain=20,
weather=20,
operator_prefs=20,
asset_constraints=20,
scenario_meta=20,
),
)
return hashlib.sha256(json.dumps(blob, sort_keys=True).encode("utf-8")).hexdigest()

# ===================================================================
# Domain Data Models (Immutable)
# ===================================================================

@dataclass(frozen=True)
class RawTelemetry:
id: str
tick: int
speed_kph: float
coolant_c: float
lane_offset_m: float
obstacle_m: float
comms_ok: bool
wall_ts: float
schema_version: str = "2.0.0"

@dataclass(frozen=True)
class NormalizedTelemetry:
id: str
tick: int
speed_norm: float
temp_norm: float
lateral_norm: float
obstacle_norm: float
comms_drop: float
raw_wall_ts: float
tick_ts: float # logical tick index as float for compatibility

@dataclass(frozen=True)
class AnomalyPacket:
id: str
tick: int
anomaly_score: float
tick_ts: float

@dataclass(frozen=True)
class RiskPacket:
id: str
tick: int
risk: float
anomaly: float
tick_ts: float

class ProposalType(Enum):
SAFETY_CRITICAL = "SAFETY_CRITICAL"
EFFICIENCY = "EFFICIENCY"
NAV_HINT = "NAV_HINT"

@dataclass(frozen=True)
class Proposal:

id: str
source_risk_id: str
tick: int
level: str # PolicyState name
suggested_action: str
risk: float
anomaly: float
tick_ts: float
policy_version: str
ptype: ProposalType

@dataclass(frozen=True)
class ReviewRecord:
id: str
proposal_id: str
operator_id: str
ts: float
note: str

@dataclass(frozen=True)
class RejectRecord:
id: str
proposal_id: str
operator_id: str

ts: float
reason: str

@dataclass(frozen=True)
class CommitRecord:
id: str
proposal_id: str
operator_id: str
tick: int
level: str
action: str
risk: float
anomaly: float
committed_at_wall_ts: float
policy_version: str
human_context: Dict[str, Any]

@dataclass(frozen=True)
class ActuationIntent:
"""
What the actuation layer should consider doing, given a human-committed decision.
This is NOT an actuator command; it's a constrained intent.
"""

id: str
commit_id: str
operator_id: str
tick: int
level: str
action: str
risk: float
anomaly: float
valid_until_ts: float
expired: bool = False
# Optional soft caps, can be ignored by downstream if not applicable
speed_cap_kph: Optional[float] = None
note: str = ""
# V10.5: deterministic revocation metadata
invalidation_reason: Optional[str] = None

@dataclass(frozen=True)
class RiskExplainPacket:
"""Explainability for a single risk computation."""

id: str
tick: int
details: Dict[str, Dict[str, float]] # feature -> {feature, weight, contribution}
anomaly: float
risk: float

tick_ts: float

@dataclass
class EpisodicMemory:
"""
Deterministic, bounded, replay-safe contextual memory.
No learning, no drift — just structured context for downstream consumers.
"""

terrain: Deque[str] = field(default_factory=lambda: deque(maxlen=20))
weather: Deque[str] = field(default_factory=lambda: deque(maxlen=20))
operator_prefs: Deque[Dict[str, Any]] = field(default_factory=lambda: deque(maxlen=20))
asset_constraints: Deque[Dict[str, Any]] = field(default_factory=lambda:
deque(maxlen=20))
scenario_meta: Deque[Dict[str, Any]] = field(default_factory=lambda:
deque(maxlen=20))

def add(self, kind: str, value: Any) -> None:
if not hasattr(self, kind):
raise ValueError(f"Unknown episodic kind '{kind}'")
q: Deque[Any] = getattr(self, kind)
q.append(deepcopy(value))

# ===================================================================
# Rolling Context

# ===================================================================

@dataclass
class RollingContext:
raw: Optional[RawTelemetry] = None
normalized: Deque[NormalizedTelemetry] = field(default_factory=lambda:
deque(maxlen=5))
anomaly: Deque[AnomalyPacket] = field(default_factory=lambda: deque(maxlen=5))
risk: Deque[RiskPacket] = field(default_factory=lambda: deque(maxlen=5))
risk_explain: Deque[RiskExplainPacket] = field(default_factory=lambda:
deque(maxlen=5))
latest_proposal: Optional[Proposal] = None
latest_intent: Optional[ActuationIntent] = None
episodic: EpisodicMemory = field(default_factory=EpisodicMemory)

def latest_norm(self) -> Optional[NormalizedTelemetry]:
return self.normalized[-1] if self.normalized else None

def latest_anom(self) -> Optional[AnomalyPacket]:
return self.anomaly[-1] if self.anomaly else None

def latest_risk(self) -> Optional[RiskPacket]:
return self.risk[-1] if self.risk else None

def latest_risk_explain(self) -> Optional[RiskExplainPacket]:
return self.risk_explain[-1] if self.risk_explain else None

# ===================================================================
# Journal + Audit
# ===================================================================

@dataclass(frozen=True)
class Event:
type: str
ts: float
payload: Any

@dataclass(frozen=True)
class JournalEntry:
seq: int
event_type: str
event_ts: float
payload: Dict[str, Any]
hash: str
prev_hash: str

class EventJournal:
"""Hash-chained event journal for replay verification."""

def __init__(self, max_len: int = 50000):
self.max_len = max_len
self.entries: List[JournalEntry] = []
self._last_hash: str = "0" * 64
self._seq: int = 0

@staticmethod
def _hash_entry(prev_hash: str, ev_type: str, ts: float, payload: Dict[str, Any]) -> str:
blob = json.dumps(
dict(prev_hash=prev_hash, type=ev_type, ts=ts, payload=payload),
sort_keys=True,
separators=(",", ":"),
).encode("utf-8")
return hashlib.sha256(blob).hexdigest()

def append(self, event: Event, payload_dict: Dict[str, Any]) -> None:
self._seq += 1
h = self._hash_entry(self._last_hash, event.type, event.ts, payload_dict)
entry = JournalEntry(
seq=self._seq,
event_type=event.type,
event_ts=event.ts,
payload=payload_dict,
hash=h,
prev_hash=self._last_hash,

)
self._last_hash = h
self.entries.append(entry)
if len(self.entries) > self.max_len:
self.entries = self.entries[-self.max_len :]

def verify_chain(self) -> bool:
prev = "0" * 64
for e in self.entries:
h = self._hash_entry(prev, e.event_type, e.event_ts, e.payload)
if h != e.hash:
return False
prev = e.hash
return True

@dataclass
class AuditEntry:
id: str
ts: float
kind: str
summary: str
meta: Dict[str, Any]

class AuditLog:

def __init__(self, max_len: int = 1000):
self.max_len = max_len
self.entries: Deque[AuditEntry] = deque(maxlen=max_len)

def add(self, kind: str, summary: str, meta: Optional[Dict[str, Any]] = None) -> None:
self.entries.append(
AuditEntry(
id=str(uuid.uuid4()),
ts=time.time(),
kind=kind,
summary=summary,
meta=meta or {},
)
)

# ===================================================================
# Core State + Snapshot
# ===================================================================

@dataclass
class CoreState:
system_status: str
system_status_reason: str
last_tick: int

run_id: str
rng_seed: int
policy_version: str
mode: str = "DEMO" # DEMO or SAFETY
events_received: int = 0
commits: List[CommitRecord] = field(default_factory=list)
module_health: Dict[str, Dict[str, Any]] = field(default_factory=dict)
muted_modules: Dict[str, str] = field(default_factory=dict) # module_id -> reason

@dataclass
class KernelSnapshot:
core: CoreState
context: RollingContext
audit_tail: List[AuditEntry]
last_journal_seq: int
last_journal_hash: str

# ===================================================================
# Policy FSM
# ===================================================================

class PolicyState(Enum):
LOW = 0 # minimal restrictions

WATCH = 1 # elevated monitoring
HOLD = 2 # slow / constrained
STOP = 3 # full stop / safe state

@dataclass
class PolicyFSM:
thresholds: Dict[str, float]
state: PolicyState = PolicyState.LOW
dwell_ticks: int = 3
_entered_state_tick: int = 0

def evaluate(self, risk: RiskPacket) -> Tuple[PolicyState, str, str, Dict[str, Any]]:
"""Evaluate risk and update FSM with hysteresis/dwell. Returns (state, action,
transition, breadcrumb)."""
r = risk.risk
tick = risk.tick
w, h, s = self.thresholds["watch"], self.thresholds["hold"], self.thresholds["stop"]

prior_state = self.state
prior_entered = self._entered_state_tick or tick

# Desired target state purely from thresholds
if r >= s:
target = PolicyState.STOP
action = "Immediate controlled stop"

elif r >= h:
target = PolicyState.HOLD
action = "Reduce speed, tighten safety margins"
elif r >= w:
target = PolicyState.WATCH
action = "Elevate monitoring"
else:
target = PolicyState.LOW
action = "Nominal"

# First-time initialization of dwell reference
if self._entered_state_tick == 0:
self._entered_state_tick = tick

# Enforce dwell: only allow transitions if we've stayed in current state for at least
dwell_ticks.
if self.state != target:
if (tick - self._entered_state_tick) >= self.dwell_ticks:
self.state = target
self._entered_state_tick = tick
transition = f"{prior_state.name}->{self.state.name}"
else:
transition = "DAMPED"
else:
transition = "STABLE"

breadcrumb = {
"tick": tick,
"prior_state": prior_state.name,
"next_state": self.state.name,
"transition": transition,
"dwell": tick - prior_entered,
"risk_vector": {
"risk": r,
"anomaly": risk.anomaly,
},
}
return self.state, action, transition, breadcrumb

# ===================================================================
# Feature Extraction + Risk Kernel
# ===================================================================

class FeatureExtractor:
"""Configurable feature pipeline."""

def __init__(self, feature_map: Dict[str, Callable[[NormalizedTelemetry], float]]):
self.feature_map = feature_map

def extract(self, norm: NormalizedTelemetry) -> Dict[str, float]:

return {name: fn(norm) for name, fn in self.feature_map.items()}

class RiskKernel:
def __init__(self, weights: Dict[str, float]):
self.weights = weights # already normalized weights

def compute_explain(
self, features: Dict[str, float], anomaly_score: float
) -> Tuple[float, Dict[str, Dict[str, float]]]:
"""
Returns (risk_value, explain_dict) where explain_dict maps feature name to:
{"feature": value, "weight": weight, "contribution": value * weight}
"""
contributions: Dict[str, Dict[str, float]] = {}
total = 0.0
for k, w in self.weights.items():
val = anomaly_score if k == "anomaly" else features.get(k, 0.0)
contrib = val * w
contributions[k] = {
"feature": float(val),
"weight": float(w),
"contribution": float(contrib),
}
total += contrib

# clamp
total = max(0.0, min(1.0, total))
return total, contributions

# ===================================================================
# Anomaly Model
# ===================================================================

class AnomalyModel(ABC):
@abstractmethod
def score(self, history: List[NormalizedTelemetry]) -> float:
...

class ZScoreAnomalyModel(AnomalyModel):
def score(self, history: List[NormalizedTelemetry]) -> float:
if len(history) < 4:
return 0.0

speeds = [n.speed_norm for n in history]
temps = [n.temp_norm for n in history]

def mean(xs: List[float]) -> float:
return sum(xs) / len(xs)

def std(xs: List[float], m: float) -> float:
return (sum((x - m) ** 2 for x in xs) / max(1, len(xs) - 1)) ** 0.5

m_s, m_t = mean(speeds), mean(temps)
s_s, s_t = std(speeds, m_s), std(temps, m_t)

latest = history[-1]

def z(x: float, m: float, s: float) -> float:
if s < 1e-6:
return 0.0
return abs((x - m) / s)

z1 = z(latest.speed_norm, m_s, s_s)
z2 = z(latest.temp_norm, m_t, s_t)

# Map combined z-score to [0,1]
return min(1.0, (z1 + z2) / 6.0)

# ===================================================================
# Telemetry Adapters (Live + Replay)
# ===================================================================

class TelemetryAdapter(ABC):
@abstractmethod
def generate_raw(self, tick: int) -> RawTelemetry:
...

class DemoVehicleAdapter(TelemetryAdapter):
def __init__(self, rng: random.Random, clock: Clock, asset_id: str = "demo_1"):
self.rng = rng
self.clock = clock
self.asset_id = asset_id

def generate_raw(self, tick: int) -> RawTelemetry:
r = self.rng
speed = 40 + 30 * (1 + r.random())
coolant = r.randint(60, 120)
lane = r.uniform(-1.5, 1.5)
obstacle = r.uniform(10, 100)
comms_ok = r.random() > 0.03
return RawTelemetry(
id=f"{self.asset_id}:{uuid.uuid4()}",
tick=tick,
speed_kph=round(speed, 1),
coolant_c=float(coolant),
lane_offset_m=round(lane, 2),
obstacle_m=round(obstacle, 1),

comms_ok=comms_ok,
wall_ts=self.clock.now(),
)

class ReplayTelemetryAdapter(TelemetryAdapter):
"""Feeds RawTelemetry from a prior journal (or list) in deterministic order."""

def __init__(self, records: List[RawTelemetry]):
# Sort by tick then id to be deterministic
self.records = sorted(records, key=lambda r: (r.tick, r.id))
self._idx = 0

def generate_raw(self, tick: int) -> RawTelemetry:
if self._idx >= len(self.records):
raise IndexError("Replay exhausted")
rec = self.records[self._idx]
self._idx += 1
return rec

# ===================================================================
# Event Bus
# ===================================================================

class EventBus:
def __init__(self, schema: Dict[str, Type[Any]]):
self.schema = schema # event_type -> payload_type
self.subscribers: Dict[str, List[Tuple[str, Callable[[Any], None]]]] = {}
self.queue: Deque[Event] = deque()

def subscribe(self, evt_type: str, module_id: str, callback: Callable[[Any], None]) -> None:
if evt_type not in self.schema:
raise ValueError(f"Unknown event type '{evt_type}'")
self.subscribers.setdefault(evt_type, []).append((module_id, callback))

def publish(self, evt_type: str, payload: Any, ts: float) -> None:
if evt_type not in self.schema:
raise ValueError(f"Unknown event type '{evt_type}'")
expected = self.schema[evt_type]
if not isinstance(payload, expected):
raise TypeError(f"Bad payload type for {evt_type}: expected {expected}, got
{type(payload)}")
self.queue.append(Event(type=evt_type, ts=ts, payload=payload))

def drain(self, sandbox_callback: Callable[[str, Event, Callable[[Any], None]], None]) ->
None:
while self.queue:
event = self.queue.popleft()
for module_id, cb in sorted(self.subscribers.get(event.type, []), key=lambda x: x[0]):
sandbox_callback(module_id, event, cb)

# ===================================================================
# Sandbox
# ===================================================================

class Sandbox:
"""
Wraps module callbacks:
- times execution
- catches exceptions
- tracks error/slow counts per module
- can auto-mute modules after repeated failures
"""

def __init__(
self,
state: CoreState,
audit: AuditLog,
max_errors_per_key: int = 5,
max_slow_per_key: int = 10,
timeout_ms: float = 15.0,
history_len: int = 32,
):
self.state = state
self.audit = audit

self.max_errors_per_key = max_errors_per_key
self.max_slow_per_key = max_slow_per_key
self.timeout_ms = timeout_ms
self.exec_times: Dict[str, Deque[float]] = {}
self.error_counts: Dict[str, int] = {}
self.slow_counts: Dict[str, int] = {}
self.history_len = history_len

def _key(self, module_id: str, evt_type: str) -> str:
return f"{module_id}:{evt_type}"

def exec(self, module_id: str, event: Event, cb: Callable[[Any], None]) -> None:
if module_id in self.state.muted_modules:
return

key = self._key(module_id, event.type)
start = time.monotonic()
try:
cb(event.payload)
except Exception as e:
count = self.error_counts.get(key, 0) + 1
self.error_counts[key] = count
self.audit.add(
"module_error",
f"{module_id} failed on {event.type}: {e!r}",
{"module": module_id, "event": event.type, "errors": count},

)
if count >= self.max_errors_per_key:
self.state.muted_modules[module_id] = "error_threshold"
self.audit.add(
"module_muted",
f"{module_id} muted after {count} errors on {event.type}",
{"module": module_id, "event": event.type},
)
finally:
dur_ms = (time.monotonic() - start) * 1000.0

# Track timing
hist = self.exec_times.setdefault(key, deque(maxlen=self.history_len))
hist.append(dur_ms)

health = self.state.module_health.setdefault(
module_id,
{
"errors": 0,
"slow_events": 0,
"p50_ms": 0.0,
"p90_ms": 0.0,
"p99_ms": 0.0,
"max_ms": 0.0,
},
)

health["errors"] = max(health["errors"], self.error_counts.get(key, 0))
health["max_ms"] = max(health["max_ms"], dur_ms)

# Recompute percentiles for this key only (cheap for small history)
sorted_hist = sorted(hist)
n = len(sorted_hist)

def pct(p: float) -> float:
if n == 0:
return 0.0
idx = min(n - 1, int(p * (n - 1)))
return sorted_hist[idx]

if n > 0:
health["p50_ms"] = pct(0.5)
health["p90_ms"] = pct(0.9)
health["p99_ms"] = pct(0.99)

# Slow-path logic
if dur_ms > self.timeout_ms:
count = self.slow_counts.get(key, 0) + 1
self.slow_counts[key] = count
self.audit.add(
"module_slow",
f"{module_id} exceeded tick budget on {event.type}: {dur_ms:.2f}ms",
{"module": module_id, "event": event.type, "dur_ms": dur_ms},

)
health["slow_events"] = max(health["slow_events"], count)
if count >= self.max_slow_per_key:
self.state.muted_modules[module_id] = "slow_threshold"
self.audit.add(
"module_muted",
f"{module_id} muted after {count} slow executions on {event.type}",
{"module": module_id, "event": event.type},
)

# ===================================================================
# Module Base
# ===================================================================

class KernelModule(ABC):
consumes: List[str] = []
produces: List[str] = []

def __init__(self, module_id: str, state: CoreState, context: RollingContext, bus: EventBus,
audit: AuditLog):
self.module_id = module_id
self.state = state
self.context = context
self.bus = bus

self.audit = audit

@abstractmethod
def on_register(self) -> None:
...

def before_tick(self) -> None:
...

def tick(self) -> None:
...

def after_tick(self) -> None:
...

# ===================================================================
# Concrete Modules
# ===================================================================

class TelemetryNormalizer(KernelModule):
consumes = ["telemetry.raw"]
produces = ["telemetry.normalized"]

def __init__(self, mid: str, state: CoreState, context: RollingContext, bus: EventBus, audit:
AuditLog, config: RiskConfig):
super().__init__(mid, state, context, bus, audit)
self.cfg = config

def on_register(self) -> None:
self.bus.subscribe("telemetry.raw", self.module_id, self.handle)

def handle(self, raw: RawTelemetry) -> None:
norm = NormalizedTelemetry(
id=raw.id,
tick=raw.tick,
speed_norm=self.cfg.normalization.clamp_norm("speed_kph", raw.speed_kph),
temp_norm=self.cfg.normalization.clamp_norm("coolant_c", raw.coolant_c),
lateral_norm=self.cfg.normalization.clamp_norm("lane_offset_m",
abs(raw.lane_offset_m)),
obstacle_norm=1.0 - self.cfg.normalization.clamp_norm("obstacle_m",
raw.obstacle_m),
comms_drop=0.0 if raw.comms_ok else 1.0,
raw_wall_ts=raw.wall_ts,
tick_ts=float(raw.tick),
)
self.context.normalized.append(norm)
self.bus.publish("telemetry.normalized", norm, ts=float(raw.tick))

class AnomalyDetector(KernelModule):

consumes = ["telemetry.normalized"]
produces = ["telemetry.anomaly"]

def __init__(self, mid: str, state: CoreState, context: RollingContext, bus: EventBus, audit:
AuditLog, anomaly_model: AnomalyModel):
super().__init__(mid, state, context, bus, audit)
self.model = anomaly_model

def on_register(self) -> None:
self.bus.subscribe("telemetry.normalized", self.module_id, self.handle)

def handle(self, norm: NormalizedTelemetry) -> None:
hist = list(self.context.normalized)
score = self.model.score(hist)
pkt = AnomalyPacket(
id=norm.id,
tick=norm.tick,
anomaly_score=score,
tick_ts=float(norm.tick),
)
self.context.anomaly.append(pkt)
self.bus.publish("telemetry.anomaly", pkt, ts=float(norm.tick))

class RiskScorer(KernelModule):
consumes = ["telemetry.normalized", "telemetry.anomaly"]

produces = ["risk.updated", "risk.explain"]

def __init__(
self,
mid: str,
state: CoreState,
context: RollingContext,
bus: EventBus,
audit: AuditLog,
kernel: RiskKernel,
extractor: FeatureExtractor,
):
super().__init__(mid, state, context, bus, audit)
self.kernel = kernel
self.extractor = extractor
self._norm_by_id: Dict[str, NormalizedTelemetry] = {}
self._anom_by_id: Dict[str, AnomalyPacket] = {}

def on_register(self) -> None:
self.bus.subscribe("telemetry.normalized", self.module_id, self.on_norm)
self.bus.subscribe("telemetry.anomaly", self.module_id, self.on_anom)

def on_norm(self, norm: NormalizedTelemetry) -> None:
self._norm_by_id[norm.id] = norm
self._try_emit(norm.id)

def on_anom(self, pkt: AnomalyPacket) -> None:
self._anom_by_id[pkt.id] = pkt
self._try_emit(pkt.id)

def _try_emit(self, id_: str) -> None:
if id_ not in self._norm_by_id or id_ not in self._anom_by_id:
return
norm = self._norm_by_id.pop(id_)
anom = self._anom_by_id.pop(id_)

features = self.extractor.extract(norm)
risk_val, explain = self.kernel.compute_explain(features, anom.anomaly_score)

pkt = RiskPacket(
id=norm.id,
tick=norm.tick,
risk=risk_val,
anomaly=anom.anomaly_score,
tick_ts=float(norm.tick),
)
self.context.risk.append(pkt)
self.bus.publish("risk.updated", pkt, ts=float(norm.tick))

explain_pkt = RiskExplainPacket(
id=norm.id,
tick=norm.tick,

details=explain,
anomaly=anom.anomaly_score,
risk=risk_val,
tick_ts=float(norm.tick),
)
self.context.risk_explain.append(explain_pkt)
self.bus.publish("risk.explain", explain_pkt, ts=float(norm.tick))

# Also journal explainability in audit for traceability
self.audit.add(
"risk_explain",
f"Risk explainability @tick={norm.tick} risk={risk_val:.3f}",
{"id": norm.id, "details": explain},
)

class DecisionGate(KernelModule):
consumes = ["risk.updated"]
produces = ["decision.proposal"]

def __init__(
self,
mid: str,
state: CoreState,
context: RollingContext,
bus: EventBus,

audit: AuditLog,
policy_fsm: PolicyFSM,
config: RiskConfig,
):
super().__init__(mid, state, context, bus, audit)
self.policy = policy_fsm
self.config = config

def on_register(self) -> None:
self.bus.subscribe("risk.updated", self.module_id, self.handle)

def _classify_type(self, pol_state: PolicyState) -> ProposalType:
if pol_state in (PolicyState.HOLD, PolicyState.STOP):
return ProposalType.SAFETY_CRITICAL
elif pol_state == PolicyState.WATCH:
return ProposalType.NAV_HINT
else:
return ProposalType.EFFICIENCY

def handle(self, pkt: RiskPacket) -> None:
new_state, action, transition, breadcrumb = self.policy.evaluate(pkt)
ptype = self._classify_type(new_state)
proposal = Proposal(
id=str(uuid.uuid4()),
source_risk_id=pkt.id,
tick=pkt.tick,

level=new_state.name,
suggested_action=action,
risk=pkt.risk,
anomaly=pkt.anomaly,
tick_ts=pkt.tick_ts,
policy_version=self.config.policy_version,
ptype=ptype,
)
self.context.latest_proposal = proposal
self.audit.add(
"policy_eval",
f"Policy {transition} @ risk={pkt.risk:.3f}",
{"risk": pkt.risk, "anomaly": pkt.anomaly, "state": new_state.name, "ptype":
ptype.value},
)
self.audit.add("policy_breadcrumb", "FSM transition", breadcrumb)
self.bus.publish("decision.proposal", proposal, ts=pkt.tick_ts)

class HumanGateAdapter(KernelModule):
"""
Human gate owns the authority to turn proposals into commitments.
In DEMO mode, auto_commit can be enabled (for non-safety-critical proposals).
In SAFETY mode, auto_commit is forbidden by the kernel invariants.

Multi-stage lifecycle:

- proposal received -> pending
- operator can review() (optional)
- operator can reject() with a reason
- operator can commit() with human_context -> actuation intent
"""

consumes = ["decision.proposal"]
produces = ["actuation.intent", "intent.invalidated"]

def __init__(
self,
mid: str,
state: CoreState,
context: RollingContext,
bus: EventBus,
audit: AuditLog,
clock: Clock,
safety_config: SafetyConfig,
auto_commit: bool = True,
):
super().__init__(mid, state, context, bus, audit)
self.clock = clock
self.auto_commit = auto_commit
self.safety_config = safety_config
self._pending: Dict[str, Proposal] = {}
self._reviews: Dict[str, List[ReviewRecord]] = {}

self._rejected: Dict[str, RejectRecord] = {}
self._cooling_start: Dict[str, int] = {} # proposal_id -> tick created

if self.state.mode == "SAFETY" and self.auto_commit:
raise RuntimeError("auto_commit must be False in SAFETY mode (human gating
invariant)")

def on_register(self) -> None:
self.bus.subscribe("decision.proposal", self.module_id, self.handle)

# -------------------------------------------------------------
# Event ingestion (proposals)
# -------------------------------------------------------------
def handle(self, proposal: Proposal) -> None:
# store pending proposal; human must act
self._pending[proposal.id] = proposal
self._cooling_start.setdefault(proposal.id, proposal.tick)
self.audit.add(
"proposal",
f"{proposal.level} → {proposal.suggested_action}",
{
"risk": proposal.risk,
"anomaly": proposal.anomaly,
"proposal_id": proposal.id,
"ptype": proposal.ptype.value,
},

)

# DEMO auto-commit path (non-safety-critical only)
if self.auto_commit and self.state.mode == "DEMO" and proposal.ptype !=
ProposalType.SAFETY_CRITICAL:
# auto-commit with dummy human context
self.commit(
proposal.id,
operator_id="demo_auto",
human_context={"auto": True, "reason": "demo_auto_commit"},
allow_cooling_override=True, # demo: ignore cooling
)

# -------------------------------------------------------------
# Operator interaction API
# -------------------------------------------------------------
def pending_proposals(self) -> List[Proposal]:
return list(self._pending.values())

def reviews_for(self, proposal_id: str) -> List[ReviewRecord]:
return self._reviews.get(proposal_id, [])

def rejected_for(self, proposal_id: str) -> Optional[RejectRecord]:
return self._rejected.get(proposal_id)

def review(self, proposal_id: str, operator_id: str, note: str) -> ReviewRecord:

proposal = self._pending.get(proposal_id)
if proposal is None:
raise RuntimeError(f"Review for unknown proposal_id={proposal_id}")
rec = ReviewRecord(
id=str(uuid.uuid4()),
proposal_id=proposal.id,
operator_id=operator_id,
ts=self.clock.now(),
note=note,
)
self._reviews.setdefault(proposal_id, []).append(rec)
self.audit.add(
"proposal_review",
f"Review by {operator_id} on {proposal_id}",
{"proposal_id": proposal_id, "note": note},
)
return rec

def reject(self, proposal_id: str, operator_id: str, reason: str) -> RejectRecord:
proposal = self._pending.pop(proposal_id, None)
if proposal is None:
raise RuntimeError(f"Reject for unknown proposal_id={proposal_id}")
rec = RejectRecord(
id=str(uuid.uuid4()),
proposal_id=proposal.id,
operator_id=operator_id,

ts=self.clock.now(),
reason=reason,
)
self._rejected[proposal_id] = rec
self.audit.add(
"proposal_reject",
f"Reject by {operator_id} on {proposal_id}",
{"proposal_id": proposal_id, "reason": reason},
)
return rec

def _cooling_active(self, proposal: Proposal) -> bool:
if proposal.level != PolicyState.STOP.name:
return False
created_tick = self._cooling_start.get(proposal.id, proposal.tick)
delta = self.state.last_tick - created_tick
return delta < self.safety_config.stop_proposal_cooling_ticks

def commit(
self,
proposal_id: str,
operator_id: str,
human_context: Optional[Dict[str, Any]] = None,
override_action: Optional[str] = None,
allow_cooling_override: bool = False,
) -> None:

proposal = self._pending.pop(proposal_id, None)
if proposal is None:
self.audit.add(
"commit_error",
f"Commit for unknown proposal_id={proposal_id}",
{"proposal_id": proposal_id},
)
return

# Policy version pinning
if proposal.policy_version != self.state.policy_version:
raise RuntimeError(
f"Policy version mismatch at commit: proposal={proposal.policy_version}, "
f"state={self.state.policy_version}"
)

# Cooling period enforcement for STOP proposals
if self._cooling_active(proposal) and not allow_cooling_override:
raise RuntimeError(
f"STOP proposal {proposal_id} still in cooling period; cannot commit yet"
)

ctx = human_context or {}
action = override_action or proposal.suggested_action
now = self.clock.now()

rec = CommitRecord(
id=str(uuid.uuid4()),
proposal_id=proposal.id,
operator_id=operator_id,
tick=proposal.tick,
level=proposal.level,
action=action,
risk=proposal.risk,
anomaly=proposal.anomaly,
committed_at_wall_ts=now,
policy_version=proposal.policy_version,
human_context=ctx,
)
self.state.commits.append(rec)
self.audit.add(
"commit",
f"{proposal.level} commit by {operator_id} → {action}",
{
"risk": proposal.risk,
"anomaly": proposal.anomaly,
"proposal_id": proposal.id,
"ptype": proposal.ptype.value,
},
)

# Emit actuation intent for downstream actuator layer.

# TTL is wall-clock based but revocation is checked deterministically at tick
boundaries.
intent = ActuationIntent(
id=str(uuid.uuid4()),
commit_id=rec.id,
operator_id=operator_id,
tick=rec.tick,
level=rec.level,
action=rec.action,
risk=rec.risk,
anomaly=rec.anomaly,
valid_until_ts=now + 2.0, # short-lived intent
speed_cap_kph=None,
note="Intent derived from human commit",
)
self.context.latest_intent = intent
self.bus.publish("actuation.intent", intent, ts=float(rec.tick))

# ===================================================================
# Graph Builder (Deterministic DAG)
# ===================================================================

def build_tick_order(modules: Dict[str, KernelModule], external_events: Optional[List[str]]
= None) -> List[str]:
# Build producer -> consumer edges based on event types

producers_by_evt: Dict[str, List[str]] = {}
consumers_by_evt: Dict[str, List[str]] = {}

for mid, m in modules.items():
for e in getattr(m, "produces", []):
producers_by_evt.setdefault(e, []).append(mid)
for e in getattr(m, "consumes", []):
consumers_by_evt.setdefault(e, []).append(mid)

edges: Dict[str, List[str]] = {mid: [] for mid in modules}
for evt, prods in producers_by_evt.items():
for p in prods:
for c in consumers_by_evt.get(evt, []):
if c == p:
continue
edges[p].append(c)

# Deduplicate and compute indegree
for m in modules:
edges[m] = sorted(set(edges[m]))

indegree: Dict[str, int] = {m: 0 for m in modules}
for m, outs in edges.items():
for o in outs:
indegree[o] += 1

# Kahn's algorithm with lexicographic tie-breaking
ready = sorted([m for m in modules if indegree[m] == 0])
order: List[str] = []
while ready:
m = ready.pop(0)
order.append(m)
for o in edges[m]:
indegree[o] -= 1
if indegree[o] == 0:
ready.append(o)
ready.sort()

if len(order) != len(modules):
raise RuntimeError(f"Module dependency graph has a cycle or is incomplete.
order={order}")

# Simple sanity: all consumed events should have a producer, except designated external
events
external = set(external_events or [])
for evt, consumers in consumers_by_evt.items():
if evt in external:
continue
if evt not in producers_by_evt:
raise RuntimeError(f"Event '{evt}' is consumed but has no producer")

return order

# ===================================================================
# Monarch Kernel V10.5
# ===================================================================

class MonarchKernelV10_5:
def __init__(
self,
config: Optional[RiskConfig] = None,
clock: Optional[Clock] = None,
seed: Optional[int] = None,
adapter: Optional[TelemetryAdapter] = None,
mode: str = "DEMO",
tick_budget_ms: float = 20.0,
safety_config: Optional[SafetyConfig] = None,
):
self.clock = clock or RealClock()
self.config = config or default_config()
self.config.validate()
self.safety_config = safety_config or SafetyConfig()
self.safety_config.validate(mode)

# deterministic RNG (seeded but still deterministic given same seed)
seed = seed if seed is not None else (int(self.clock.now() * 1000) & 0xFFFFFFFF)
self.rng = random.Random(seed)

# core state
self.state = CoreState(
system_status="INIT",
system_status_reason="",
last_tick=0,
run_id=str(uuid.uuid4()),
rng_seed=seed,
policy_version=self.config.policy_version,
mode=mode,
)
self.context = RollingContext()
self.audit = AuditLog()
self.journal = EventJournal()

# config attestation
self._config_hash = hash_config(self.config, self.safety_config)

# event bus
self.bus = EventBus(
schema={
"telemetry.raw": RawTelemetry,
"telemetry.normalized": NormalizedTelemetry,
"telemetry.anomaly": AnomalyPacket,
"risk.updated": RiskPacket,
"risk.explain": RiskExplainPacket,

"decision.proposal": Proposal,
"actuation.intent": ActuationIntent,
"intent.invalidated": ActuationIntent,
}
)

# sandbox
self.sandbox = Sandbox(self.state, self.audit)

# telemetry adapter
self.adapter = adapter or DemoVehicleAdapter(self.rng, self.clock)

# feature extractor + kernel + policy
feature_map = dict(
speed_norm=lambda n: n.speed_norm,
temp_norm=lambda n: n.temp_norm,
lateral_norm=lambda n: n.lateral_norm,
obstacle_norm=lambda n: n.obstacle_norm,
comms_drop=lambda n: n.comms_drop,
)
self.feature_extractor = FeatureExtractor(feature_map)
self.risk_kernel = RiskKernel(self.config.normalized_weights())
self.policy_fsm = PolicyFSM(self.config.thresholds)

# modules
self.modules: Dict[str, KernelModule] = {}

self._register(
"telemetry_normalizer",
lambda mid: TelemetryNormalizer(mid, self.state, self.context, self.bus, self.audit,
self.config),
)
self._register(
"anomaly_detector",
lambda mid: AnomalyDetector(mid, self.state, self.context, self.bus, self.audit,
ZScoreAnomalyModel()),
)
self._register(
"risk_scorer",
lambda mid: RiskScorer(
mid,
self.state,
self.context,
self.bus,
self.audit,
self.risk_kernel,
self.feature_extractor,
),
)
self._register(
"decision_gate",
lambda mid: DecisionGate(
mid,
self.state,

self.context,
self.bus,
self.audit,
self.policy_fsm,
self.config,
),
)
# In DEMO mode we allow auto_commit (configurable); in SAFETY, it must be False.
auto_commit = (mode == "DEMO" and self.safety_config.allow_auto_commit_in_demo)
self._register(
"human_gate",
lambda mid: HumanGateAdapter(
mid,
self.state,
self.context,
self.bus,
self.audit,
self.clock,
self.safety_config,
auto_commit=auto_commit,
),
)

self.tick_order = build_tick_order(self.modules, external_events=["telemetry.raw"])
self.state.system_status = "READY"

# tick budget
self.tick_budget_ms = tick_budget_ms
self._over_budget_streak = 0

# ----------------------------------------
# Module registration
# ----------------------------------------
def _register(self, module_id: str, factory: Callable[[str], KernelModule]) -> None:
if module_id in self.modules:
raise ValueError(f"Duplicate module id {module_id}")
module = factory(module_id)
self.modules[module_id] = module
module.on_register()

# ----------------------------------------
# Replay helpers
# ----------------------------------------
@staticmethod
def replay_adapter_from_journal(journal: EventJournal) -> ReplayTelemetryAdapter:
"""Build a replay adapter from a prior journal (using telemetry.raw events)."""
records: List[RawTelemetry] = []
for e in journal.entries:
if e.event_type == "telemetry.raw":
payload = dict(e.payload)
records.append(RawTelemetry(**payload))
return ReplayTelemetryAdapter(records)

# ----------------------------------------
# Journaling
# ----------------------------------------
def _journal_event(self, event_type: str, ts: float, payload: Dict[str, Any]) -> None:
ev = Event(type=event_type, ts=ts, payload=payload)
self.journal.append(ev, payload)

def _sandbox_cb(self, module_id: str, event: Event, cb: Callable[[Any], None]) -> None:
# journal event (payload as dict if dataclass), except telemetry.raw which
# is journaled at ingest boundary to avoid duplicates.
if event.type != "telemetry.raw":
payload = event.payload
if hasattr(payload, "__dataclass_fields__"):
payload_dict = asdict(payload)
else:
payload_dict = {"value": repr(payload)}
self.journal.append(event, payload_dict)

# run sandbox
self.sandbox.exec(module_id, event, cb)
self.state.events_received += 1

# ----------------------------------------
# Tick integrity checks
# ----------------------------------------

def _validate_tick_integrity(self) -> None:
# Minimal consistency checks
if self.context.raw is None:
self.audit.add("integrity_warn", "No raw telemetry in context after tick", {})

# If a proposal exists, there should be at least one risk packet
if self.context.latest_proposal and not self.context.risk:
self.audit.add(
"integrity_warn",
"Proposal exists but no risk history in context",
{},
)

# Intent expiry invariant: if latest intent is expired, mark and degrade
li = self.context.latest_intent
if li and not li.expired and li.valid_until_ts < self.clock.now():
# V10.5 hardened invalidation
reason = "expired"
invalidated = ActuationIntent(
id=li.id,
commit_id=li.commit_id,
operator_id=li.operator_id,
tick=li.tick,
level=li.level,
action=li.action,
risk=li.risk,

anomaly=li.anomaly,
valid_until_ts=li.valid_until_ts,
expired=True,
speed_cap_kph=li.speed_cap_kph,
note=li.note + f" (invalidated:{reason})",
invalidation_reason=reason,
)
self.context.latest_intent = invalidated
self.bus.publish("intent.invalidated", invalidated, ts=float(self.state.last_tick))
self.audit.add(
"intent_invalidated",
f"Intent {li.id} invalidated",
{"intent_id": li.id, "tick": self.state.last_tick, "reason": reason},
)
self.state.system_status = "DEGRADED"
self.state.system_status_reason = "Intent invalidation"

# Journal tamper check
if self.safety_config.fail_on_journal_tamper and not self.journal.verify_chain():
self.audit.add("journal_tamper", "Journal hash chain verification failed", {})
self.state.system_status = "DEGRADED"
self.state.system_status_reason = "Journal tamper detected"

# ----------------------------------------
# Core tick
# ----------------------------------------

def tick(self) -> None:
# Config attestation – if config mutated at runtime, degrade and stop ticks
current_hash = hash_config(self.config, self.safety_config)
if current_hash != self._config_hash:
self.state.system_status = "DEGRADED"
self.state.system_status_reason = "Config attestation failed (config mutated)"
self.audit.add(
"config_tamper",
"Config hash mismatch detected at tick boundary",
{"expected": self._config_hash, "actual": current_hash},
)
return

if self.state.system_status not in ("READY", "RUNNING"):
# in degraded/shutdown we don't advance logic
self.audit.add(
"tick_skipped",
"Tick requested but system not RUNNING/READY",
{"status": self.state.system_status},
)
return

self.state.system_status = "RUNNING"
self.state.last_tick += 1
tick = self.state.last_tick
tick_start_perf = time.monotonic()

# Journal tick.start boundary
self._journal_event("tick.start", float(tick), {"tick": tick})

# before_tick (deterministic order)
for mid in self.tick_order:
m = self.modules[mid]
try:
m.before_tick()
except Exception as e:
self.audit.add("module_error", f"{mid}.before_tick failed: {e!r}", {"module": mid})

# ingest raw
raw = self.adapter.generate_raw(tick)
self.context.raw = raw
# journal raw ingest as a separate event for replay integrity
self._journal_event("telemetry.raw", float(tick), asdict(raw))
self.bus.publish("telemetry.raw", raw, ts=float(tick))

# process events through sandbox
self.bus.drain(self._sandbox_cb)

# tick() on modules
for mid in self.tick_order:
m = self.modules[mid]
try:

m.tick()
except Exception as e:
self.audit.add("module_error", f"{mid}.tick failed: {e!r}", {"module": mid})

# after_tick on modules
for mid in self.tick_order:
m = self.modules[mid]
try:
m.after_tick()
except Exception as e:
self.audit.add("module_error", f"{mid}.after_tick failed: {e!r}", {"module": mid})

# integrity checks
self._validate_tick_integrity()

# Journal tick.end boundary
self._journal_event("tick.end", float(tick), {"tick": tick})

# Global tick budget enforcement
dur_ms = (time.monotonic() - tick_start_perf) * 1000.0
if dur_ms > self.tick_budget_ms:
self._over_budget_streak += 1
self.audit.add(
"tick_budget",
f"Tick {tick} exceeded global budget: {dur_ms:.2f}ms
(budget={self.tick_budget_ms}ms)",

{
"tick": tick,
"dur_ms": dur_ms,
"budget_ms": self.tick_budget_ms,
"streak": self._over_budget_streak,
},
)
if self.state.mode == "SAFETY" and self._over_budget_streak >=
self.safety_config.max_overbudget_streak:
self.state.system_status = "DEGRADED"
self.state.system_status_reason = "Global tick budget exceeded repeatedly"
else:
self._over_budget_streak = 0

# ----------------------------------------
# Snapshot + Heartbeat
# ----------------------------------------
def snapshot(self) -> KernelSnapshot:
# Tail of audit log (convert deque -> list)
audit_tail = list(self.audit.entries)[-100:]
last_j = self.journal.entries[-1] if self.journal.entries else None
return KernelSnapshot(
core=deepcopy(self.state),
context=deepcopy(self.context),
audit_tail=deepcopy(audit_tail),
last_journal_seq=last_j.seq if last_j else 0,

last_journal_hash=last_j.hash if last_j else "0" * 64,
)

def heartbeat(self) -> Dict[str, Any]:
ctx = self.context
latest_risk = ctx.latest_risk()
latest_proposal = ctx.latest_proposal
latest_intent = ctx.latest_intent
latest_explain = ctx.latest_risk_explain()
return dict(
tick=self.state.last_tick,
status=self.state.system_status,
status_reason=self.state.system_status_reason,
mode=self.state.mode,
policy_state=self.policy_fsm.state.name,
latest_risk=asdict(latest_risk) if latest_risk else None,
latest_proposal=asdict(latest_proposal) if latest_proposal else None,
latest_intent=asdict(latest_intent) if latest_intent else None,
latest_risk_explain=asdict(latest_explain) if latest_explain else None,
commits=[asdict(c) for c in self.state.commits[-5:]],
module_health=self.state.module_health,
muted_modules=self.state.muted_modules,
episodic=dict(
terrain=list(ctx.episodic.terrain),
weather=list(ctx.episodic.weather),
operator_prefs=list(ctx.episodic.operator_prefs),

asset_constraints=list(ctx.episodic.asset_constraints),
scenario_meta=list(ctx.episodic.scenario_meta),
),
)

# ----------------------------------------
# Episodic memory setters (external API hooks)
# ----------------------------------------
def remember_terrain(self, label: str) -> None:
self.context.episodic.add("terrain", label)

def remember_weather(self, label: str) -> None:
self.context.episodic.add("weather", label)

def remember_operator_pref(self, pref: Dict[str, Any]) -> None:
self.context.episodic.add("operator_prefs", pref)

def remember_asset_constraints(self, constraints: Dict[str, Any]) -> None:
self.context.episodic.add("asset_constraints", constraints)

def remember_scenario_meta(self, meta: Dict[str, Any]) -> None:
self.context.episodic.add("scenario_meta", meta)

# ===================================================================
# CLI Demo

# ===================================================================

def run_demo(
ticks: int,
interval: float,
seed: Optional[int],
mode: str,
tick_budget_ms: float,
json_out: bool,
) -> None:
kernel = MonarchKernelV10_5(config=default_config(), seed=seed, mode=mode,
tick_budget_ms=tick_budget_ms)
print("Monarch V10.5 initialized.")
print("Run ID:", kernel.state.run_id)
print("Policy version:", kernel.state.policy_version)
print("Mode:", kernel.state.mode)
print("Modules:", ", ".join(kernel.modules.keys()))
print("Tick order:", " -> ".join(kernel.tick_order))
print("----------------------------------------")

for _ in range(ticks):
kernel.tick()
hb = kernel.heartbeat()
if json_out:
print(json.dumps(hb))

else:
line = f"[tick {hb['tick']:02d}] status={hb['status']} ({hb['status_reason'] or 'OK'})"
if hb["latest_risk"]:
r = hb["latest_risk"]
line += f" risk={r['risk']:.3f} (anom={r['anomaly']:.3f}) state={hb['policy_state']}"
print(line)
if hb["latest_proposal"]:
lp = hb["latest_proposal"]
print(f"→ {lp['level']} :: {lp['suggested_action']}")
if hb["latest_intent"]:
li = hb["latest_intent"]
exp = " (expired)" if li.get("expired") else ""
inv = f" [invalidated:{li.get('invalidation_reason')}]" if li.get("invalidation_reason")
else ""
print(
f" intent: level={li['level']} action={li['action']} "
f"op={li['operator_id']}{exp}{inv}"
)
if hb["muted_modules"]:
print("Muted modules:", hb["muted_modules"])
kernel.clock.sleep(interval)

if not json_out:
print("\nRecent commits:")
for c in kernel.state.commits[-5:]:
rec = c if isinstance(c, dict) else asdict(c)

ts_str = time.strftime("%H:%M:%S", time.localtime(rec["committed_at_wall_ts"]))
print(
f" [{ts_str}] {rec['level']} — {rec['action']} "
f"(risk={rec['risk']:.3f}) by {rec['operator_id']} "
f"(policy={rec['policy_version']})"
)

def parse_args(argv=None):
p = argparse.ArgumentParser("Monarch V10.5 — Autonomy Safety Kernel Demo")
p.add_argument("--ticks", type=int, default=20)
p.add_argument("--interval", type=float, default=0.2)
p.add_argument("--seed", type=int, default=None)
p.add_argument("--mode", type=str, default="DEMO", choices=["DEMO", "SAFETY"])
p.add_argument("--tick-budget-ms", type=float, default=20.0)
p.add_argument("--json", action="store_true", help="Emit JSON heartbeat per tick")
return p.parse_args(argv)

if __name__ == "__main__":
args = parse_args()
run_demo(
ticks=args.ticks,
interval=args.interval,
seed=args.seed,
mode=args.mode,

tick_budget_ms=args.tick_budget_ms,
json_out=args.json,
)
