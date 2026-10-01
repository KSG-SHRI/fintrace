"""FINTRACE: offline, evidence-linked market incident reconstruction (stdlib only)."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import statistics
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


def instant(value: str) -> datetime:
    """Require an unambiguous ISO-8601 instant; normalize it to UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timezone required: {value}")
    return parsed.astimezone(timezone.utc)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def seal(records: list[dict], cutoff: str, key: bytes | None = None) -> dict:
    """Reject future records and seal the accepted snapshot with a hash chain."""
    limit = instant(cutoff)
    accepted = []
    rejected = []
    for record in records:
        for field in ("id", "kind", "event_at", "available_at", "source"):
            if field not in record:
                raise ValueError(f"{field} missing from record")
        event_at, available_at = instant(record["event_at"]), instant(record["available_at"])
        if available_at < event_at:
            raise ValueError(f"record {record['id']} available before its event")
        if event_at > limit or available_at > limit:
            rejected.append(record["id"])
            continue
        accepted.append(record)
    if len({r["id"] for r in accepted}) != len(accepted):
        raise ValueError("duplicate record id")
    accepted.sort(key=lambda r: (r["available_at"], r["id"]))
    previous = "0" * 64
    chain = []
    for record in accepted:
        previous = hashlib.sha256(bytes.fromhex(previous) + canonical(record)).hexdigest()
        chain.append(previous)
    manifest = {"cutoff": limit.isoformat(), "record_count": len(accepted),
                "record_hashes": [digest(r) for r in accepted], "root": previous}
    if key is not None:
        manifest["hmac_sha256"] = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    return {"manifest": manifest, "records": accepted, "rejected_future_ids": rejected}


def verify(bundle: dict, key: bytes | None = None) -> bool:
    manifest = bundle["manifest"]
    rebuilt = seal(bundle["records"], manifest["cutoff"])
    if rebuilt["rejected_future_ids"] or rebuilt["manifest"] != {k: v for k, v in manifest.items() if k != "hmac_sha256"}:
        return False
    if "hmac_sha256" in manifest:
        if key is None:
            return False
        unsigned = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
        return hmac.compare_digest(manifest["hmac_sha256"], hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest())
    return True


def _bars(records: list[dict], ticker: str) -> list[dict]:
    bars = [r for r in records if r["kind"] == "bar" and r.get("ticker") == ticker]
    bars.sort(key=lambda r: r["event_at"])
    for bar in bars:
        if bar.get("close", 0) <= 0 or bar.get("volume", -1) < 0:
            raise ValueError(f"invalid bar {bar['id']}")
    return bars


def _return(bars: list[dict]) -> float | None:
    return bars[-1]["close"] / bars[-2]["close"] - 1 if len(bars) >= 2 else None


def _z(value: float, history: list[float]) -> float | None:
    if len(history) < 3:
        return None
    spread = statistics.pstdev(history)
    return (value - statistics.mean(history)) / spread if spread > 0 else None


def reconstruct(bundle: dict, ticker: str, peers: list[str], window_minutes: int = 90,
                key: bytes | None = None) -> dict:
    if not verify(bundle, key):
        raise ValueError("snapshot integrity check failed")
    cutoff = instant(bundle["manifest"]["cutoff"])
    records = bundle["records"]
    target = _bars(records, ticker)
    if len(target) < 2:
        raise ValueError("target needs at least two bars by cutoff")
    latest = target[-1]
    current = _return(target)
    previous_returns = [target[i]["close"] / target[i - 1]["close"] - 1 for i in range(1, len(target) - 1)]
    return_z = _z(current, previous_returns)
    volume_z = _z(latest["volume"], [b["volume"] for b in target[:-1]])
    peer_moves = {}
    peer_ids = {}
    for peer in peers:
        if peer == ticker:
            continue
        bars = _bars(records, peer)
        if len(bars) >= 2 and instant(bars[-1]["event_at"]) == instant(latest["event_at"]):
            peer_moves[peer] = _return(bars)
            peer_ids[peer] = bars[-1]["id"]
    basket = statistics.median(peer_moves.values()) if peer_moves else None
    residual = current - basket if basket is not None else None
    start = instant(latest["event_at"]) - timedelta(minutes=window_minutes)
    events = sorted((r for r in records if r["kind"] != "bar" and start <= instant(r["event_at"]) <= instant(latest["event_at"])),
                    key=lambda r: (r["event_at"], r["id"]))
    scored = []
    for event in events:
        age = abs((instant(latest["event_at"]) - instant(event["event_at"])).total_seconds()) / 60
        relevance = 1.0 if event.get("ticker") == ticker else 0.75 if event.get("kind") == "macro" else 0.35
        score = round(relevance * math.exp(-age / 30), 4)
        scored.append({"id": event["id"], "event_at": event["event_at"], "kind": event["kind"],
                       "source": event["source"], "summary": event.get("summary", ""), "temporal_score": score})
    scored.sort(key=lambda e: e["temporal_score"], reverse=True)
    if basket is None:
        assessment = "Insufficient synchronized peers for a market-wide comparison."
    elif abs(basket) > 0.002 and current * basket > 0 and abs(residual) < abs(current) * 0.5:
        assessment = "Peer co-movement is consistent with a broad repricing; cause is not established."
    else:
        assessment = "The target move differs from peers; investigate issuer-specific evidence."
    return {"ticker": ticker, "as_of": cutoff.isoformat(), "snapshot_root": bundle["manifest"]["root"],
            "target_bar_id": latest["id"], "return_pct": round(current * 100, 4),
            "return_z": None if return_z is None else round(return_z, 4),
            "volume_z": None if volume_z is None else round(volume_z, 4),
            "peer_returns_pct": {p: round(v * 100, 4) for p, v in peer_moves.items()},
            "cross_asset_edges": [{"from": ticker, "to": p, "evidence_ids": [latest["id"], peer_ids[p]],
                                   "same_direction": current * v > 0,
                                   "return_gap_pct": round((current - v) * 100, 4)} for p, v in peer_moves.items()],
            "peer_median_pct": None if basket is None else round(basket * 100, 4),
            "residual_pct": None if residual is None else round(residual * 100, 4),
            "timeline": scored, "assessment": assessment,
            "limitations": ["Temporal proximity and co-movement are not proof of causation.",
                            "Historical availability is only as trustworthy as the supplied source timestamps.",
                            "Options, news and media authenticity need separately licensed or supplied records."]}


def sec_filings(cik: str, user_agent: str, cutoff: str) -> list[dict]:
    """Import SEC submission metadata, not filing text. Respect SEC's declared User-Agent policy."""
    if not (cik.isdigit() and len(cik) <= 10):
        raise ValueError("CIK must be at most 10 digits")
    if "@" not in user_agent:
        raise ValueError("Use a contactable User-Agent, e.g. Name email@example.com")
    url = f"https://data.sec.gov/submissions/CIK{int(cik):010d}.json"
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept-Encoding": "identity"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.load(response)
    recent = data["filings"]["recent"]
    results = []
    for i, accession in enumerate(recent["accessionNumber"]):
        raw = recent["acceptanceDateTime"][i]
        accepted = datetime.fromisoformat(raw).replace(tzinfo=ZoneInfo("America/New_York")).astimezone(timezone.utc)
        when = accepted.isoformat()
        if accepted <= instant(cutoff):
            results.append({"id": f"sec:{accession}", "kind": "filing", "event_at": when,
                            "available_at": when, "ticker": None, "source": url,
                            "summary": f"SEC {recent['form'][i]} filing accepted ({accession})"})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("analyze", help="seal records and generate an evidence-linked report")
    demo.add_argument("records", type=Path)
    demo.add_argument("--ticker", required=True)
    demo.add_argument("--peers", nargs="*", default=[])
    demo.add_argument("--cutoff", required=True)
    demo.add_argument("--output", type=Path, default=Path("report.json"))
    demo.add_argument("--signing-key-env", help="optional environment variable containing an HMAC key")
    sec = sub.add_parser("sec", help="fetch SEC filing metadata for manual inclusion in records")
    sec.add_argument("--cik", required=True)
    sec.add_argument("--user-agent", required=True)
    sec.add_argument("--cutoff", required=True)
    args = parser.parse_args()
    if args.command == "sec":
        print(json.dumps(sec_filings(args.cik, args.user_agent, args.cutoff), indent=2))
        return
    source = json.loads(args.records.read_text())
    key = os.environ[args.signing_key_env].encode() if args.signing_key_env else None
    bundle = seal(source["records"], args.cutoff, key)
    report = reconstruct(bundle, args.ticker, args.peers, key=key)
    args.output.write_text(json.dumps({"report": report, "bundle": bundle}, indent=2) + "\n")
    print(f"Wrote {args.output}; excluded {len(bundle['rejected_future_ids'])} future records")


if __name__ == "__main__":
    main()
