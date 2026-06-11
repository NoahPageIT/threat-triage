"""HTTP helper: routes HTTPS through the OS certificate store (so it works behind
SSL-inspecting proxies) and caches responses to respect API rate limits."""
import urllib.request
import urllib.parse
import urllib.error
import json
import ssl
import time
import os
import hashlib

# Use the operating-system trust store. On Windows this includes any corporate /
# proxy root CA, so calls succeed where Python's bundled certifi would fail.
_CTX = ssl.create_default_context()
try:
    _CTX.load_default_certs(ssl.Purpose.SERVER_AUTH)
except Exception:
    pass
# Some SSL-inspecting proxies present a root CA whose BasicConstraints extension
# isn't marked critical, which OpenSSL's strict RFC-5280 mode rejects. Relax that
# single pedantic check while keeping full chain/hostname verification.
if hasattr(ssl, "VERIFY_X509_STRICT"):
    _CTX.verify_flags &= ~ssl.VERIFY_X509_STRICT
# Last-resort escape hatch for fully non-compliant intercepting proxies / lab use.
if os.environ.get("THREATTRIAGE_INSECURE") == "1":
    _CTX.check_hostname = False
    _CTX.verify_mode = ssl.CERT_NONE

CACHE_DIR = os.path.join(os.path.dirname(__file__), os.pardir, ".cache")


def _cache_file(key):
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
    return os.path.join(CACHE_DIR, digest + ".json")


def request(url, method="GET", headers=None, json_data=None, form_data=None,
            timeout=15, cache_ttl=3600):
    """Return parsed JSON (or {'_raw': text} / {'_error': msg})."""
    key = "|".join([method, url, json.dumps(json_data, sort_keys=True) if json_data else "",
                    urllib.parse.urlencode(form_data) if form_data else ""])
    cf = _cache_file(key)
    if cache_ttl and os.path.exists(cf) and time.time() - os.path.getmtime(cf) < cache_ttl:
        try:
            with open(cf, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass

    hdrs = {"User-Agent": "ThreatTriage/1.0", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    elif form_data is not None:
        body = urllib.parse.urlencode(form_data).encode("utf-8")
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            text = resp.read().decode("utf-8", "replace")
        try:
            out = json.loads(text)
        except ValueError:
            out = {"_raw": text}
    except urllib.error.HTTPError as e:
        out = {"_error": "HTTP %s" % e.code, "_status": e.code}
    except Exception as e:
        out = {"_error": str(e)}

    if "_error" not in out:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cf, "w", encoding="utf-8") as fh:
                json.dump(out, fh)
        except Exception:
            pass
    return out
