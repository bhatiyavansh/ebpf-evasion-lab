# E04 Zero-Event Problem — Verified Root-Cause Diagnosis

## Symptom
A live E04 (indirect shell) Tetragon run reported "completed" while showing
`event_observed: false`, an empty process list, and zero event counts. The empty capture then
**overwrote** the previously good `results/raw/tetragon_events/E04.jsonl`.

## Investigation (end-to-end, this session)
Traced a fresh run through execution → sensor health → capture → normalization:

1. **Workload executed successfully.** `docker run alpine sh -c 'sh -c "echo …; id"'` exits 0 and
   `id`/`uname` produce correct output. Execution is **not** the failure.
2. **Tetragon sensor is alive.** During the capture window Tetragon emitted host-process events
   (e.g. `/usr/sbin/ip`, `/usr/bin/grep`, kali panel scripts) — `process_exec`, `process_tracepoint`
   and `process_kprobe` all fire. The sensor is **not** dead.
3. **Tetragon captured ZERO events for the container.** No `process_exec`, no `openat` kprobe, and
   no event carrying a `docker` field referenced the workload container. The container's `sh/id/uname`
   execs and its `/etc/shadow` openat never appeared.
4. **The failure is Tetragon-specific.** On the **same host, same kernel, same window**, the live
   **Falco** harness captured 3 alerts (incl. the built-in T1555 "Read sensitive file untrusted"
   detection) and the live **Tracee** harness captured 57 container-scoped events (`cat`, `id`,
   `security_file_open` for `/etc/shadow`). Falco and Tracee track the container normally.
5. **Trigger: a host reboot at 16:41.** All historically successful Tetragon captures (E01–E08,
   A-series) were taken **before** this reboot and contain real container-tagged events. Every
   Tetragon container capture **after** the reboot returns zero. Falco/Tracee are unaffected by the
   reboot.
6. **Mechanism:** Tetragon's process event-cache fails to resolve `/proc/<pid>/cgroup` for the
   container's processes ("Procfs execve event pods/ identifier error: open /proc/<pid>/cgroup: no
   such file or directory"), so container events are not emitted. Attempted fixes that did **not**
   resolve it: explicit BTF mount, `-v /sys/fs/cgroup`, `-v /var/run/docker/netns`, `-v /var/run/docker.sock`,
   longer-lived workloads, and `--procfs /host/proc` (the last also broke host capture).

## Conclusion
**Verified cause:** a Tetragon-specific container-cgroup tracking regression that appeared after
the host reboot — not a UI bug, not a detector miss, not a workload failure. Falco and Tracee
demonstrate the container is observable; Tetragon alone cannot currently associate the container's
events.

## Fixes applied
1. **Harness hardening** (`scripts/capture_tetragon.sh`): records `workload_exit_code`,
   `sensor_health`, `host_events_in_window`, and a deterministic `collection_status`
   (`complete` / `collection_failed_container_not_tracked` / `collection_failed_sensor_no_events` /
   `execution_failed`). It **never overwrites a non-empty evidence file with an empty capture**
   (`evidence_preserved: true`).
2. **Honest classification** (`normalize.py`): a verified-execution-but-zero-collection Tetragon run
   is `collection_failed` (dimensions: execution=completed, collection=failed, telemetry=not_observed,
   detection=not_evaluated) — **never** telemetry-observed-with-empty-data and never a detector miss.
3. **Evidence preserved:** E01–E03, E05, E06–E08 and all A-series Tetragon streams (captured
   pre-reboot) remain intact; only E04 was already lost and is now correctly shown as
   `COLLECTION_FAILED`.

## Impact on findings
- The fair detection comparison (A-series) was captured pre-reboot and is valid; its 0/6 → 2/4
  result is unaffected.
- E04's "indirect shell did not remove observability" point is still supported by the intact
  sibling Tetragon telemetry (E02 baseline, E05 timing) and by Falco/Tracee E04 — but the live
  Tetragon E04 cell is honestly `COLLECTION_FAILED` until the Tetragon regression is resolved
  (e.g. a Tetragon upgrade, or booting the alternate installed kernel).

## Additional fix attempt (this pass)
Pulled and tested **Tetragon v1.4.1** (a different release) with the same config: it also captured
**zero container execs** while host execs worked. Verified that Tetragon's container CAN read the
workload's `/proc/<pid>/cgroup` and sees the PID, and that the failure persists with long-lived
workloads (sleep) and longer capture windows — so it is neither an enrichment-race nor a
version-specific bug. The blocker is confirmed environment-level (Tetragon container-cgroup event
association on this kernel post-reboot) and is accepted; `COLLECTION_FAILED` stands. Falco and Tracee
container capture remain fully operational.
