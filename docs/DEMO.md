# Five-Minute Faculty Demo Script

A tight walkthrough that shows the system is **working, reproducible, and honest**.

## The fastest path: the guided `/demo` route

Open **`http://localhost:3000/demo`** and press **→** (or Next) through 7 acts. It is a
full-screen, keyboard-navigable presentation (←/→ to move, Restart to reset) that runs the
whole story, including a real live run or recorded replay in Act 2. This is the recommended
surface for a faculty demo. The manual walkthrough below is the same story if you prefer to
drive the routes yourself.

## Before the demo (one-time setup)

```bash
cd ~/ebpf-evasion-lab
./scripts/setup_node.sh && source .toolchain/activate.sh
cd dashboard && npm install && npm run build && npm run start   # http://localhost:3000
```

Leave the server running. Confirm Docker is up and the three detector images are present:

```bash
./scripts/lab.sh status      # expect docker_available:true, images_present all true
```

---

## The 5 minutes

**0:00 — Framing (Command Centre).**
"This platform evaluates three eBPF runtime-security systems — Falco, Tracee, Tetragon —
against baseline and adaptive container behaviors. The guiding principle is distinguishing
*what the kernel saw* from *what a security policy actually detected*."
Point at the five metric cards: **3 detectors, 5 experiments, 15/15 evaluated, 15 with
evidence, 0 incomplete.**

**0:45 — The status model.**
"Five statuses, assigned by an auditable Python classifier, not by trusting a raw flag.
Crucially, Tracee and Tetragon are telemetry-only here, so their events are *telemetry
observed*, never *detection*." Show the Status Model panel counts (4 detection / 10 telemetry
/ 1 partial).

**1:30 — The matrix (Comparisons tab).**
Walk E01→E05. Hit the honest points:
- E01 Falco is a **built-in security detection**; the others are telemetry (Tetragon now
  confirms `/etc/shadow` in the openat pathname).
- E03 Falco is **Partial** — "the connection was *visible* in Tracee as a connect to :443,
  but no tool raised a network-specific detection. That's a rule-coverage gap, not a
  blindness."

**2:30 — Baseline → Adaptive.**
"E04 adds a shell layer; E05 adds 2-second delays. Across all three tools, every execution
stage stayed visible. So: simple indirection and timing variation did **not** reduce
observability here — and we explicitly do *not* claim that proves immunity."

**3:15 — Live proof (Live & Replay tab → Live run).**
Select **E04**, show the exact command, click **Prepare run → Confirm & start**.
"This starts Tetragon as a privileged container, runs the benign workload, scopes the
captured eBPF events to that exact container, and regenerates the whole analysis pipeline."
In ~10 seconds: **STATE: COMPLETED**, and the captured result shows `sh → sh → id` derived
from live events. "Nothing here is mocked — that JSON came from the kernel a moment ago."

**4:00 — Evidence & integrity.**
Switch to **Recorded replay**, open any experiment's raw `.jsonl` — "every number traces to
an immutable event file." Then, in a terminal:

```bash
python3 -I scripts/validate.py      # 34 checks pass
```

"These tests enforce the integrity rules: telemetry-only tools can never be marked a
detection, detection rates exclude untested cells, and no latency number is invented."

**4:45 — Close.**
"Headline: strong, robust *visibility* everywhere; sparse *detection*, concentrated in
Falco's built-in sensitive-file rule. The visibility-vs-detection gap — clearest in the E03
network case — is exactly where the next experiments go: network policies, Tracee signatures,
and exec-less mechanisms like io_uring."

---

## Exact commands to reproduce the demonstration

```bash
# 1. Toolchain + dashboard
./scripts/setup_node.sh
source .toolchain/activate.sh
cd dashboard && npm install && npm run build && npm run start   # open http://localhost:3000
cd ..

# 2. Live detector health
./scripts/lab.sh status

# 3. Run a controlled experiment live (also available in the dashboard)
./scripts/lab.sh run-tetragon E04

# 4. Regenerate normalized results + analysis + CSV, and validate
./scripts/pipeline.sh

# 5. Standalone validation
python3 -I scripts/validate.py

# 6. Clean up lab containers (only lab-managed ones)
./scripts/lab.sh down
```

## If the live run can't be shown (no Docker / privileged restriction)

Use **Recorded replay** exclusively — it is clearly labeled "Recorded evidence", preserves
original captured events, and needs no running detector. The entire narrative above works
from recorded evidence; only beat **3:15** changes from live to replay.
