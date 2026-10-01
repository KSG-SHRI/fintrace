# FINTRACE — market incident forensics, with an as-of boundary

FINTRACE asks: **what evidence was available when a market move happened?** Given a ticker, timestamp, and timestamped records, it seals an as-of snapshot, detects unusual price/volume behavior, compares synchronized peers, ranks nearby events, and emits a cited JSON incident report. It **does not** prove a cause or recommend trades.

This is a runnable **offline MVP**, not a deployed real-time financial AI platform. The included incident is entirely synthetic. No historical-event accuracy, fraud-detection accuracy, or options/deepfake capability is claimed.

## Run it

Python 3.11+; no third-party packages.

```bash
python -m unittest discover -v
python fintrace.py analyze examples/synthetic_incident.json --ticker XYZ --peers PEER1 PEER2 --cutoff 2025-04-03T14:30:00Z --output report.json
```

The synthetic `future1` headline is at 14:31 and must be excluded at the 14:30 cutoff. The report contains a SHA-256 snapshot root, source IDs for cross-asset edges, return and volume anomaly scores (or `null` when history is insufficient), a ranked event timeline, and explicit limitations. The `bundle` beside the report lets another process rerun integrity checks.

For optional HMAC authentication, put a secret key in an environment variable and pass its **name** via `--signing-key-env`. Do not commit or paste the key. Signing detects later edits **if the verifier already trusts the key**; it does not prove an external publisher's original timestamp.

## Record contract and Time Machine

Every record needs a unique `id`, `kind`, timezone-aware ISO-8601 `event_at`, `available_at`, and `source`. Both timestamps must be at or before the cutoff. `available_at` means when a record could first have been known, **not** the date later assigned to a revised observation. Bars also need `ticker`, positive `close`, and nonnegative `volume`. Peer bars must align exactly with the target's latest timestamp.

`seal()` rejects future records before analysis and hashes accepted records into an ordered chain. `verify()` detects changed accepted records; optional HMAC detects forgery when the key is not held by an attacker. Analysis is offline after sealing. **This is not a cryptographic proof that a historical source was genuinely available then, nor a sandbox preventing all network access.** Backtests need trusted point-in-time archives and revision/vintage handling. A contemporary scrape of an old document alone is not enough.

## What the report computes

- Latest-bar return and volume z-scores relative to prior observations; insufficient or zero-variance history gives `null`.
- Median synchronized peer return and target-minus-peer residual. Cross-asset edges cite exact input bar IDs; these are **co-movement edges, not causal edges**.
- Simple event relevance × exponential time-distance score with exact event IDs and sources. Events after the move are excluded even if the analysis cutoff is later.
- A conservative broad-vs-issuer-specific heuristic that says “consistent with” or “investigate,” never “caused by.”

A future learned ranker or LLM can only sit *after* sealed retrieval and must cite record IDs; it must not invent missing evidence.

## Source adapters and limitations

`python fintrace.py sec --cik 1045810 --user-agent 'Researcher name contact@example.com' --cutoff 2025-04-03T14:30:00Z` retrieves recent **SEC filing metadata** (form and acceptance time), not a filing-text diff. Use a contactable User-Agent and respect SEC fair-access rules. Older filings may be in additional submission files not handled here. Acceptance timestamps are interpreted in America/New_York and converted to UTC. Check timestamp/provenance before merging the records into a study.

No price vendor, licensed options feed, news corpus, earnings-transcript parser, synthetic-media detector, or LLM is silently substituted. Historical FRED/ALFRED vintages are needed for macro data because revised observations are not necessarily what traders saw then. See the [SEC EDGAR API](https://www.sec.gov/search-filings/edgar-application-programming-interfaces), [SEC developer guidance](https://www.sec.gov/about/developer-resources), and [FRED real-time periods](https://fred.stlouisfed.org/docs/api/fred/realtime_period.html).

## Research path

1. Curate timestamp-verified incidents with independent sources and adjudicated, potentially multi-label explanations. Separate detection, retrieval, and attribution quality.
2. Compare against nearest-headline, price-only anomaly, and peer-movement baselines. Report evidence-retrieval precision/recall, calibration, abstention rate, and citation validity on chronological out-of-sample splits.
3. Add licensed options/news feeds and actual document/media authenticity modules behind the same point-in-time record contract; test planted headlines and revised macro releases.
4. Only then add a grounded language-model narrative. Human investigators should review high-impact fraud allegations.

The code and tests implement the first auditable slice of this plan. **Not investment advice.**
