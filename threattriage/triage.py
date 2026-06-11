"""Orchestrate enrichers across an indicator and compute an aggregate risk verdict."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from .indicators import classify
from . import enrichers


def triage(indicator):
    itype, ind = classify(indicator)
    if itype == "unknown":
        return {"indicator": ind, "type": itype, "score": 0, "verdict": "UNKNOWN",
                "results": [], "flagged_by": [],
                "note": "Could not classify as IP, file hash, domain, or URL."}

    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(fn, itype, ind) for fn in enrichers.ALL]
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception:
                r = None
            if r is not None:
                results.append(r)
    results.sort(key=lambda r: (not r["available"], r["source"]))

    confident = [r["score"] for r in results if r["available"] and r["score"] is not None]
    risk = max(confident) if confident else 0
    flagged = [r["source"] for r in results if r["available"] and (r["score"] or 0) >= 50]
    if len(flagged) >= 2:                       # corroboration bumps confidence
        risk = min(100, risk + 5)

    verdict = "MALICIOUS" if risk >= 70 else "SUSPICIOUS" if risk >= 40 else "CLEAN"
    return {"indicator": ind, "type": itype, "score": risk, "verdict": verdict,
            "results": results, "flagged_by": flagged}
