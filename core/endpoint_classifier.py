"""
core/endpoint_classifier.py — Module 1: Endpoint Classification & API Asset Inventory.
Classifies discovered endpoints into categories and builds an API inventory record.
"""

import re
from urllib.parse import urlparse

# ── Classification Rules ──────────────────────────────────────────────────────

# Ordered from most specific to least — first match wins
CLASSIFICATION_RULES = [
    # Admin APIs
    ("Admin",   r"/(admin|management|manager|superuser|staff|cms|backoffice|console|control)"),
    # Auth APIs
    ("Auth",    r"/(auth|login|logout|signin|signup|register|token|refresh|oauth|sso|saml|mfa|2fa|password|reset|verify|confirm)"),
    # Payment APIs
    ("Payment", r"/(pay|payment|billing|invoice|checkout|order|subscription|charge|refund|wallet|transaction|cart)"),
    # User APIs
    ("User",    r"/(user|users|profile|account|me|member|customer|contact|address|avatar)"),
    # Data / Search APIs
    ("Data",    r"/(search|query|report|export|import|data|analytics|metrics|statistics|audit|log)"),
    # Health / Status
    ("Health",  r"/(health|status|ping|ready|live|version|info|metrics)"),
    # Public (fallback for anything else that looks like a public resource)
    ("Public",  r""),
]


def classify_endpoint(path: str, method: str = "GET") -> str:
    """Classify a single endpoint into a semantic category."""
    path_lower = path.lower()
    for category, pattern in CLASSIFICATION_RULES:
        if pattern and re.search(pattern, path_lower):
            return category
    return "Public"


def classify_endpoints(endpoints: list[dict]) -> list[dict]:
    """Add 'category' field to every endpoint in the list."""
    classified = []
    for ep in endpoints:
        ep_copy = dict(ep)
        if not ep_copy.get("category"):
            ep_copy["category"] = classify_endpoint(ep_copy.get("path", "/"), ep_copy.get("method", "GET"))
        classified.append(ep_copy)
    return classified


def get_classification_summary(endpoints: list[dict]) -> dict:
    """Return a count summary of endpoint categories."""
    summary = {}
    for ep in endpoints:
        cat = ep.get("category") or classify_endpoint(ep.get("path", "/"), ep.get("method", "GET"))
        summary[cat] = summary.get(cat, 0) + 1
    return summary


# ── API Inventory Builder ─────────────────────────────────────────────────────

def _detect_version(base_url: str, endpoints: list[dict], spec_info: dict = None) -> str | None:
    """Detect the API version from URL patterns or OpenAPI spec."""
    # From spec
    if spec_info and spec_info.get("version"):
        return spec_info["version"]

    # From base URL or common endpoint paths
    version_pattern = re.compile(r"/v(\d+(?:\.\d+)?)")
    for ep in endpoints:
        m = version_pattern.search(ep.get("path", ""))
        if m:
            return f"v{m.group(1)}"

    # From base_url itself
    m = version_pattern.search(base_url)
    if m:
        return f"v{m.group(1)}"

    return None


def _detect_api_name(base_url: str, spec_info: dict = None) -> str:
    """Infer a human-readable API name."""
    if spec_info and spec_info.get("title"):
        return spec_info["title"]

    parsed = urlparse(base_url)
    hostname = parsed.hostname or "Unknown API"
    port     = parsed.port
    name     = hostname.replace("www.", "").replace("localhost", "Local").title()
    if port and port not in (80, 443):
        name += f" :{port}"
    return f"{name} API"


def _detect_primary_auth(endpoints: list[dict]) -> str | None:
    """Determine the most common auth type across endpoints."""
    counts: dict[str, int] = {}
    for ep in endpoints:
        auth = ep.get("auth_type")
        if auth:
            counts[auth] = counts.get(auth, 0) + 1
    if not counts:
        return None
    return max(counts, key=counts.__getitem__)


def build_api_inventory(
    base_url: str,
    endpoints: list[dict],
    spec_info: dict = None,
) -> dict:
    """
    Build a complete API inventory record from discovered endpoints.

    Args:
        base_url:   The scanned API base URL.
        endpoints:  List of discovered endpoint dicts (with 'category' key set).
        spec_info:  Optional dict with {'title', 'version'} from OpenAPI spec.

    Returns:
        dict matching the ApiInventory model fields.
    """
    classified = classify_endpoints(endpoints)
    summary    = get_classification_summary(classified)

    auth_eps   = sum(1 for ep in classified if ep.get("auth_required"))
    public_eps = len(classified) - auth_eps

    return {
        "api_name":        _detect_api_name(base_url, spec_info),
        "base_url":        base_url.rstrip("/"),
        "version":         _detect_version(base_url, classified, spec_info),
        "auth_type":       _detect_primary_auth(classified),
        "total_endpoints": len(classified),
        "public_count":    summary.get("Public", 0) + summary.get("Health", 0) + summary.get("Data", 0),
        "auth_count":      summary.get("Auth", 0) + auth_eps,
        "admin_count":     summary.get("Admin", 0),
        "swagger_url":     None,  # Caller can fill this in
    }
