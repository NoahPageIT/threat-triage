"""Classify an indicator of compromise into a type."""
import re
import ipaddress

_HASH = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")


def classify(indicator):
    """Return (type, normalized) where type is ip|hash|domain|url|unknown."""
    ind = (indicator or "").strip().strip('"').strip("'")
    if not ind:
        return "unknown", ind
    # IP (v4 or v6)
    try:
        return "ip", str(ipaddress.ip_address(ind))
    except ValueError:
        pass
    # File hash
    if re.fullmatch(r"[A-Fa-f0-9]+", ind) and len(ind) in _HASH:
        return "hash", ind.lower()
    # URL
    if re.match(r"^[a-z]+://", ind, re.I):
        return "url", ind
    # Domain / hostname
    if _DOMAIN_RE.match(ind):
        return "domain", ind.lower()
    return "unknown", ind


def hash_kind(h):
    return _HASH.get(len(h), "unknown")
