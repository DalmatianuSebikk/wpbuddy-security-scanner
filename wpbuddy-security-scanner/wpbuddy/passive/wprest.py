"""WordPress REST API (/wp-json/) discovery - one of the stealthiest recon
techniques available: a single GET that returns the site's REST index.

- reveals which plugins registered their own REST namespaces
  (e.g. "contact-form-7/v1", "wc/v3" for WooCommerce)
- /wp-json/wp/v2/users often returns the full user list in one request
  (when it's not blocked) - much quieter than looping over user ids
"""

from .. import httpclient

# Namespaces registered by WordPress core; anything else belongs to a plugin.
CORE_NAMESPACES = {
    "oembed/1.0", "oembed/1.0/embed", "wp/v2", "wp/v2", "wp-block-editor/v1",
    "wp-block-editor/v2", "wp-site-health/v1", "wp-site-health/v2",
}


def discover_rest_namespaces(target):
    """Return the list of non-core REST namespaces (plugin fingerprints)."""
    payload = httpclient.get_json(f"{target}wp-json/")
    if not isinstance(payload, dict):
        return None  # REST disabled, WAF'd, or not JSON - not an error
    namespaces = [n for n in payload.get("namespaces", []) if n not in CORE_NAMESPACES]
    return namespaces


def users_via_rest_collection(target):
    """Try GET /wp-json/wp/v2/users (single request).

    `per_page=100` matters: the default caps the listing at 10 users, so
    larger sites leak only a slice without it. Returns a list of
    (name, slug), [] when accessible but empty, or None when the endpoint is
    blocked/disabled.
    """
    for url in (f"{target}wp-json/wp/v2/users?per_page=100",
                f"{target}?rest_route=/wp/v2/users&per_page=100"):
        payload = httpclient.get_json(url)
        if isinstance(payload, list):  # a dict here is an error object
            return [(u.get("name", ""), u.get("slug", "")) for u in payload if isinstance(u, dict)]
    return None
