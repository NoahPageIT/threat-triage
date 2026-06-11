"""Threat-intel enrichers. Each returns a normalized result:

    {source, available, score (0-100 or None), verdict, summary, details}

No-key sources (ip-api, GreyNoise community, abuse.ch ThreatFox/URLhaus) run by
default. Key-based sources (AbuseIPDB, VirusTotal, OTX) activate when their API
key is present in the environment.
"""
import os
import base64
from . import http
from .indicators import hash_kind


def _result(source, available, score, verdict, summary, details=None):
    return {"source": source, "available": available, "score": score,
            "verdict": verdict, "summary": summary, "details": details or {}}


# ---- no-key sources --------------------------------------------------------

def ipapi(itype, ind):
    if itype != "ip":
        return None
    r = http.request("http://ip-api.com/json/%s?fields=status,country,city,isp,org,as,reverse,hosting,proxy" % ind)
    if r.get("status") != "success":
        return _result("ip-api (GeoIP)", False, None, "error", r.get("_error", "lookup failed"))
    flags = []
    if r.get("hosting"): flags.append("hosting/datacenter")
    if r.get("proxy"): flags.append("proxy/VPN")
    summary = "%s, %s - %s (%s)" % (r.get("city") or "?", r.get("country") or "?",
                                    r.get("org") or r.get("isp") or "?", r.get("as") or "?")
    if flags:
        summary += " [" + ", ".join(flags) + "]"
    # geo is informational, but proxy/hosting slightly raises suspicion
    score = 25 if (r.get("proxy") or r.get("hosting")) else None
    return _result("ip-api (GeoIP)", True, score, "info", summary, r)


def isc(itype, ind):
    """Internet Storm Center (SANS) - IP reputation, no key required."""
    if itype != "ip":
        return None
    r = http.request("https://isc.sans.edu/api/ip/%s?json" % ind)
    ipd = (r or {}).get("ip")
    if r.get("_status") == 404 or (ipd and not ipd.get("count")):
        return _result("ISC SANS", True, 0, "clean", "no attack reports")
    if not ipd or r.get("_error"):
        return _result("ISC SANS", False, None, "error", r.get("_error", "no data"))
    count = int(ipd.get("count") or 0)
    attacks = int(ipd.get("attacks") or 0)
    if count == 0:
        return _result("ISC SANS", True, 0, "clean", "no attack reports")
    score = min(90, 30 + attacks)
    verdict = "malicious" if attacks >= 10 else "suspicious"
    return _result("ISC SANS", True, score, verdict,
                   "%s reports across %s distinct targets" % (count, attacks), ipd)


def greynoise(itype, ind):
    if itype != "ip":
        return None
    r = http.request("https://api.greynoise.io/v3/community/%s" % ind)
    if r.get("_status") == 404:
        return _result("GreyNoise", True, 0, "clean", "not observed scanning the internet")
    if r.get("_status") == 401:
        return _result("GreyNoise", False, None, "no-key", "set GREYNOISE_API_KEY to enable")
    if r.get("_error"):
        return _result("GreyNoise", False, None, "error", r["_error"])
    cls = r.get("classification", "unknown")
    name = r.get("name", "")
    score = {"malicious": 85, "benign": 5}.get(cls)
    verdict = {"malicious": "malicious", "benign": "clean"}.get(cls, "info")
    msg = r.get("message", "")
    summary = "classification: %s%s%s" % (cls, " (%s)" % name if name and name != "unknown" else "",
                                          " - %s" % msg if msg and cls == "unknown" else "")
    return _result("GreyNoise", True, score, verdict, summary, r)


def threatfox(itype, ind):
    if itype not in ("ip", "domain", "hash", "url"):
        return None
    headers = {}
    key = os.environ.get("ABUSE_CH_API_KEY")
    if key:
        headers["Auth-Key"] = key
    r = http.request("https://threatfox-api.abuse.ch/api/v1/", method="POST",
                     headers=headers, json_data={"query": "search_ioc", "search_term": ind})
    status = r.get("query_status")
    if status == "no_result":
        return _result("ThreatFox (abuse.ch)", True, 0, "clean", "no known IOC match")
    if status == "ok" and r.get("data"):
        d = r["data"][0]
        fam = d.get("malware_printable") or d.get("malware") or "unknown"
        conf = d.get("confidence_level", 75)
        return _result("ThreatFox (abuse.ch)", True, max(80, int(conf)), "malicious",
                       "listed IOC - malware: %s (confidence %s%%)" % (fam, conf), d)
    if r.get("_status") == 401 or status == "no_auth":
        return _result("ThreatFox (abuse.ch)", False, None, "no-key",
                       "set ABUSE_CH_API_KEY (free at abuse.ch) to enable")
    if r.get("_error") or status == "illegal_search_term":
        return _result("ThreatFox (abuse.ch)", False, None, "error", r.get("_error", status))
    return _result("ThreatFox (abuse.ch)", True, 0, "clean", "no match")


# ---- key-based sources -----------------------------------------------------

def abuseipdb(itype, ind):
    if itype != "ip":
        return None
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return _result("AbuseIPDB", False, None, "no-key", "set ABUSEIPDB_API_KEY to enable")
    r = http.request("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90" % ind,
                     headers={"Key": key})
    d = (r or {}).get("data")
    if not d:
        return _result("AbuseIPDB", False, None, "error", r.get("_error", "no data"))
    sc = int(d.get("abuseConfidenceScore", 0))
    verdict = "malicious" if sc >= 50 else "clean"
    return _result("AbuseIPDB", True, sc, verdict,
                   "%s%% abuse confidence, %s reports" % (sc, d.get("totalReports", 0)), d)


def virustotal(itype, ind):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return _result("VirusTotal", False, None, "no-key", "set VT_API_KEY to enable")
    ep = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}.get(itype)
    if not ep:
        return None
    ident = base64.urlsafe_b64encode(ind.encode()).decode().strip("=") if itype == "url" else ind
    r = http.request("https://www.virustotal.com/api/v3/%s/%s" % (ep, ident), headers={"x-apikey": key})
    attr = (((r or {}).get("data") or {}).get("attributes")) or {}
    stats = attr.get("last_analysis_stats")
    if not stats:
        return _result("VirusTotal", False, None, "error", r.get("_error", "no analysis"))
    mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    score = round((mal + susp) / total * 100)
    verdict = "malicious" if mal >= 3 else "suspicious" if (mal + susp) else "clean"
    return _result("VirusTotal", True, score, verdict,
                   "%s/%s engines flagged it malicious/suspicious" % (mal + susp, total), stats)


def otx(itype, ind):
    key = os.environ.get("OTX_API_KEY")
    if not key:
        return _result("AlienVault OTX", False, None, "no-key", "set OTX_API_KEY to enable")
    section = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}.get(itype)
    if not section:
        return None
    seg = {"ip": "IPv4", "domain": "domain", "url": "url",
           "hash": "file"}[itype]
    r = http.request("https://otx.alienvault.com/api/v1/indicators/%s/%s/general" % (seg, ind),
                     headers={"X-OTX-API-KEY": key})
    pulses = ((r or {}).get("pulse_info") or {}).get("count", 0)
    if r.get("_error"):
        return _result("AlienVault OTX", False, None, "error", r["_error"])
    score = 60 if pulses else 0
    verdict = "suspicious" if pulses else "clean"
    return _result("AlienVault OTX", True, score, verdict,
                   "%s threat-intel pulse(s) reference this indicator" % pulses, r.get("pulse_info"))


ALL = [ipapi, isc, greynoise, threatfox, abuseipdb, virustotal, otx]
