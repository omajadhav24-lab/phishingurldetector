from urllib.parse import urlparse
import ipaddress


def is_ip_address(domain):
    if not domain:
        return False

    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def analyze_url(url):
    parsed = urlparse(url)

    domain = parsed.hostname
    url_lower = url.lower()

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "update",
        "secure",
        "account",
        "password",
        "signin",
        "confirm"
    ]

    found_keywords = [
        word for word in suspicious_keywords
        if word in url_lower
    ]

    features = {
        "scheme": parsed.scheme,
        "domain": domain,
        "path": parsed.path,
        "query": parsed.query,
        "url_length": len(url),

        "uses_https": parsed.scheme == "https",

        "uses_ip_address": is_ip_address(domain),

        "contains_at_symbol": "@" in url,

        "suspicious_keywords": found_keywords,

        "suspicious_keyword_count": len(found_keywords)
    }

    return features