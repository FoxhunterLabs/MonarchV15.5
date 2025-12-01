________________________________________
Monarch V10.5 — Agnostic Autonomy Safety Kernel
Graph-Driven · FSM Policy · Replay-Deterministic · Human-Gated
Monarch V10.5 is a deterministic, safety-first autonomy kernel designed for environments where automation must never bypass human authority.
It provides a bounded, replay-verifiable core for converting telemetry → normalized signals → anomaly detection → risk scoring → policy state → proposals → human-gated actuation intents.
The system exposes no direct actuator controls. All actions flow through a human operator or an authorized auto-commit path in DEMO mode for non-critical actions.
________________________________________
Key Safety Invariants
•	Human-Gated Automation
The kernel never sends actuator commands. It produces intents, which downstream controllers may evaluate.
•	Proposal Lifecycle
proposal → (review | reject | commit) → intent.
All commits are human-authored except optional demo auto-commit.
•	Modes
o	DEMO: optional auto-commit for non-safety-critical proposals
o	SAFETY: human approval required for every action
•	Replay Determinism
A full hash-chained journal allows exact replay, verification, and tamper detection.
________________________________________
What’s New in V10.5
1.	Episodic Memory Layer
Deterministic, bounded, drift-free contextual memory (terrain, weather, operator_prefs, etc.).
2.	FSM Audit Breadcrumbs
Every risk evaluation logs finite-state-machine transitions with dwell, deltas, and risk vectors.
3.	Hardened Intent TTL Enforcement
Intents now produce deterministic invalidation events, with chain-of-custody metadata.
4.	Risk Explainability Packets
Per-feature weights, values, and contributions included for traceability.
________________________________________
Architecture Overview
Raw Telemetry
     ↓
TelemetryNormalizer  — clamps, normalizes, timestamps
     ↓
AnomalyDetector      — Z-score model w/ bounded history
     ↓
RiskScorer           — weighted feature contributions + explainability
     ↓
DecisionGate (FSM)   — LOW / WATCH / HOLD / STOP + breadcrumbs
     ↓
HumanGateAdapter     — human review + commit → ActuationIntent
The kernel executes via a deterministic DAG built from producer/consumer relationships.
Modules run under a sandbox enforcing execution budgets, percentiles, slow-path detection, and auto-muting.
________________________________________
Major Components
Rolling Context
A short-horizon state window (normalized, anomaly, risk, risk_explain, latest_proposal, latest_intent, episodic memory).
Event Journal
All internal events are hashed (sha256(prev_hash + payload + ts)), enabling replay verification.
Policy FSM
Maps risk scores to states with dwell/hysteresis:
State	Meaning
LOW	nominal
WATCH	elevated monitoring
HOLD	constrained mobility
STOP	safe stop
Transition breadcrumbs are stored in the audit log.
Episodic Memory
Deterministic context inputs for downstream supervisory layers. Strict maxlen ensures replay safety.
________________________________________
Configuration
RiskConfig
Defines feature weights, risk thresholds, and normalization ranges.
SafetyConfig
Defines global invariants (max overbudget streak, cooling ticks for STOP proposals, auto-commit permissions, etc.).
Config Attestation
On each tick, the kernel checks a stable hash of all safety-critical configs.
If mutated → system enters DEGRADED and halts advancement.
________________________________________
Actuation Intents
A committed proposal yields a short-lived ActuationIntent with:
•	operator ID
•	action string
•	valid-until timestamp
•	optional soft caps (e.g., speed limit)
•	deterministic invalidation record
Intents are not actuator commands.
________________________________________
Replay Mode
Use ReplayTelemetryAdapter to run Monarch deterministically from a prior journal:
adapter = MonarchKernelV10_5.replay_adapter_from_journal(old_journal)
kernel = MonarchKernelV10_5(adapter=adapter, mode="SAFETY")
Journal entries must verify cleanly or the kernel degrades.
________________________________________
Running the Demo
python3 monarch.py --ticks 50 --interval 0.1 --mode DEMO
JSON mode for programmatic consumption:
python3 monarch.py --json
CLI Args
Flag	Description
--ticks	Number of ticks to run
--interval	Wall-clock spacing between ticks
--seed	Deterministic RNG seed
--mode	DEMO or SAFETY
--tick-budget-ms	Global tick execution budget
--json	Emit JSON heartbeat per tick
________________________________________
Extending Monarch
Add a new module
1.	Subclass KernelModule
2.	Declare consumes and produces
3.	Call bus.subscribe in on_register
4.	Implement your event handlers
5.	Register via _register(...)
The DAG will automatically order modules based on event flow.
Add new features to risk scoring
Extend the feature_map in kernel initialization:
feature_map["yaw_rate_norm"] = lambda n: clamp(...)
Update weights and normalization ranges in your RiskConfig.
________________________________________
Safety Notes
•	No runtime mutation of configs or modules is permitted without triggering DEGRADE.
•	Journal verification failure also forces DEGRADE.
•	STOP proposals include enforced cooling ticks before commits are allowed.
•	Auto-commit is never allowed when mode = SAFETY.
________________________________________
Snapshot & Heartbeat API
snap = kernel.snapshot()
hb = kernel.heartbeat()
Heartbeat includes:
•	latest risk/anomaly/proposal/intent
•	FSM state
•	system status + reason
•	module health metrics
•	episodic memory tail
•	latest commits
Useful for dashboards and teleoperation UIs.
________________________________________
License
MIT
________________________________________
