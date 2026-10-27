# TraceWeaver Evaluation (auto-generated)

- git `d02ce979c3` · engine `2.0.0` · schema `1.0.0` · config `2e474f9325cd33ab` · 2026-10-25T18:40:35+00:00
- Eligible trials: **52** · ineligible: {'baseline/training split': 44, 'ambiguous label (A2)': 3, 'ambiguous label (A3)': 3, 'visibility=COLLECTION_FAILED': 1, 'no supervised label for scenario E06': 5, 'no supervised label for scenario E07': 2, 'no supervised label for scenario E08': 1}
- Anomaly threshold: 0.2 · labels: {'A1': 'positive', 'A5': 'positive', 'A6': 'positive', 'A7': 'negative', 'A2': 'ambiguous', 'A3': 'ambiguous'}

| Method | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|--------|----|----|----|----|-----------|--------|----|-----|
| rules_only | 20 | 0 | 6 | 26 | 1.0 (20) | 0.4348 (46) | 0.6061 | 0.0 (6) |
| anomaly_only | 33 | 0 | 6 | 13 | 1.0 (33) | 0.7174 (46) | 0.8354 | 0.0 (6) |
| combined | 43 | 0 | 6 | 3 | 1.0 (43) | 0.9348 (46) | 0.9663 | 0.0 (6) |

**Caveats:** Small, exploratory sample — not a statistically powered study. The anomaly baseline is fit only on the train-split streams (benign/baseline), which are excluded from these metrics to avoid leakage. 'Flag' means surfaced-as-suspicious; a verified DETECTED still requires P>0. A2/A3 are ambiguous and excluded; E-series are observability baselines and excluded.
