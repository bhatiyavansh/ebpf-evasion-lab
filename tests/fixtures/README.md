# Synthetic test fixtures — NOT real evidence

Every file here is a **synthetic** fixture used only by `tests/test_traceweaver.py`.
Records carry `"_synthetic": true`. These files live under `tests/` and are **never**
read by the real evidence pipeline (`scripts/traceweaver/pipeline.py`, which reads
only `results/raw/`), so synthetic data cannot be promoted to live evidence (enforced
by provenance check P3).
