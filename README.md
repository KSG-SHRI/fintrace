# FINTRACE — market incident forensics, with an as-of boundary

FINTRACE asks: **what evidence was available when a market move happened?** Given a ticker, timestamp, and timestamped records, it seals an as-of snapshot, detects unusual price/volume behavior, compares synchronized peers, ranks nearby events, and emits a cited JSON incident report. It **does not** prove a cause or recommend trades.

This is a runnable **offline MVP**, not a deployed real-time financial AI platform. The included incident is entirely synthetic. No historical-event accuracy, fraud-detection accuracy, or options/deepfake capability is claimed.

## Run it

Python 3.11+; no third-party packages.

```bash
python -m unittest discover -v
python fintrace.py analyze examples/synthetic_incident.json --ticker XYZ --peers PEER1 PEER2 --cutoff 2025-04-03T14:30:00Z --output report.json
python fintrace.py verify report.json
```

The synthetic `future1` headline is at 14:31 and must be excluded at the 14:30 cutoff. The report contains a SHA-256 snapshot root, all four bar IDs for each cross-asset comparison, return and volume anomaly scores (or `null` when history is insufficient), a ranked event timeline, and explicit limitations. The `bundle` beside the report lets another process reproduce the full report.

For optional HMAC authentication, put a secret key in an environment variable and pass its **name** via `--signing-key-env` to both `analyze` and `verify`. Do not commit or paste the key. Signing detects later edits **if the verifier already trusts the key**; it does not prove an external publisher's original timestamp.

## Record contract and Time Machine

Every record needs a unique `id`, `kind`, timezone-aware ISO-8601 `event_at`, `available_at`, and `source`. Both timestamps must be at or before the cutoff. `available_at` means when a record could first have been known, **not** the date later assigned to a revised observation. Bars also need `ticker`, positive finite `close`, and nonnegative finite `volume`. Duplicate bar timestamps are rejected. Peer bars must align with **both endpoints** of the target return interval.

`seal()` rejects future records before analysis and hashes accepted records into an ordered chain. `verify()` detects changed accepted records; `verify_incident()` reruns analysis and detects edits to the report. Optional HMAC authenticates a bundle only to someone who already trusts the key. Analysis is offline after sealing. **This is not a cryptographic proof that a historical source was genuinely available then, nor a sandbox preventing all network access.** The `rejected_future_ids` audit list is not signed. Backtests need trusted point-in-time archives and revision/vintage handling. A contemporary scrape of an old document alone is not enough.

## What the report computes

- Latest-bar return and volume z-scores relative to prior observations; insufficient or zero-variance history gives `null`.
- Median synchronized peer return and target-minus-peer residual. Cross-asset edges cite all four return-endpoint IDs; these are **co-movement edges, not causal edges**.
- Simple event relevance × exponential time-distance score with exact event IDs and sources. Events or publications after the last target bar are excluded even if the analysis cutoff is later. This score is a heuristic, **not a calibrated probability**.
- A conservative broad-vs-issuer-specific heuristic that says “consistent with” or “investigate,” never “caused by.”

A future learned ranker or LLM can only sit *after* sealed retrieval and must cite record IDs; it must not invent missing evidence.

## Engineering checks and threat model

The 12 regression tests cover future-data exclusion, post-move publication, mixed time-zone offsets, unsynchronized peers, duplicate IDs/bar times, non-finite values, sparse-history abstention, snapshot tampering, and report tampering. CI runs the same tests and a CLI demo. These are **synthetic/adversarial correctness tests, not historical attribution metrics**.

An attacker controlling the input can fabricate timestamps, prices, headlines, or source names; hashes cannot stop that. An attacker holding the HMAC key can re-sign a forged bundle. A real retrospective study needs trusted first-seen archives, a revision policy, independently labeled incidents, and independent market/news data. Until then, present FINTRACE as an auditable prototype, not a fraud detector or trading system.

## Source adapters and limitations

`python fintrace.py sec --cik 1045810 --user-agent 'Researcher name contact@example.com' --cutoff 2025-04-03T14:30:00Z` retrieves recent **SEC filing metadata** (form and acceptance time), not a filing-text diff. Use a contactable User-Agent and respect SEC fair-access rules. Older filings may be in additional submission files not handled here. Acceptance timestamps are interpreted in America/New_York and converted to UTC. Check timestamp/provenance before merging the records into a study.

No price vendor, licensed options feed, news corpus, earnings-transcript parser, synthetic-media detector, or LLM is silently substituted. Historical FRED/ALFRED vintages are needed for macro data because revised observations are not necessarily what traders saw then. See the [SEC EDGAR API](https://www.sec.gov/search-filings/edgar-application-programming-interfaces), [SEC developer guidance](https://www.sec.gov/about/developer-resources), and [FRED real-time periods](https://fred.stlouisfed.org/docs/api/fred/realtime_period.html).

## Research path

1. Curate timestamp-verified incidents with independent sources and adjudicated, potentially multi-label explanations. Separate detection, retrieval, and attribution quality.
2. Compare against nearest-headline, price-only anomaly, and peer-movement baselines. Report evidence-retrieval precision/recall, calibration, abstention rate, and citation validity on chronological out-of-sample splits.
3. Add licensed options/news feeds and actual document/media authenticity modules behind the same point-in-time record contract; test planted headlines and revised macro releases.
4. Only then add a grounded language-model narrative. Human investigators should review high-impact fraud allegations.

The code and tests implement the first auditable slice of this plan. **Not investment advice.**
