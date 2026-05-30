import pytest
from app.security.link_inspector import (
    extract_urls,
    validate_url_scheme,
    is_unsafe_ip,
    inspect_link
)

def test_extract_urls_normalization():
    """
    Verify URL extraction matches correctly and normalizes characters
    using the NFC canonical form.
    """
    # URL in text with combining diaeresis "o" which should compose into a single NFC character
    text = "Please verify: https://example.com/co\u0308operation"
    urls = extract_urls(text)
    assert len(urls) == 1
    # Composed NFC form is \u00f6
    assert urls[0] == "https://example.com/c\u00f6operation"

def test_extract_urls_www_prefix():
    """
    Verify URL extraction prepends http:// to www. prefixes.
    """
    text = "Visit www.phish-defense.org/auth for details"
    urls = extract_urls(text)
    assert len(urls) == 1
    assert urls[0] == "http://www.phish-defense.org/auth"

def test_forbidden_schemes():
    """
    Verify that validate_url_scheme blocks non-http/https schemes.
    """
    forbidden = [
        "file:///etc/passwd",
        "ftp://mirror.net/file",
        "gopher://local",
        "dict://localhost",
        "data:text/html;base64,123",
        "mailto:test@example.com"
    ]
    for url in forbidden:
        with pytest.raises(ValueError, match="Forbidden URL scheme"):
            validate_url_scheme(url)

    # Verify HTTP and HTTPS are allowed
    assert validate_url_scheme("http://example.com") == "http"
    assert validate_url_scheme("https://example.com") == "https"

def test_unsafe_ip_blocking():
    """
    Verify that is_unsafe_ip blocks standard private networks, loopback,
    link-local, unspecified, and the explicit CGNAT, NAT64, and 6to4 ranges.
    """
    unsafe_addresses = [
        # Loopback
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.255",
        "::1",
        # RFC 1918 Private
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.100",
        # Link-local
        "169.254.169.254",
        "fe80::1",
        # CGNAT
        "100.64.0.1",
        "100.127.255.254",
        # NAT64
        "64:ff9b::1",
        "64:ff9b::ffff:ffff",
        # 6to4
        "2002:c0a8:101::",
        # Unspecified / Multicast / Broadcast
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "ff02::1"
    ]
    for ip in unsafe_addresses:
        assert is_unsafe_ip(ip) is True

def test_safe_ip_allowing():
    """
    Verify that is_unsafe_ip returns False for valid public IP addresses.
    """
    safe_addresses = [
        "8.8.8.8",
        "93.184.216.34",  # example.com
        "1.1.1.1",
        "2606:4700::6810:7a60"  # Cloudflare DNS IPv6
    ]
    for ip in safe_addresses:
        assert is_unsafe_ip(ip) is False

@pytest.mark.asyncio
async def test_inspect_link_loopback_blocked():
    """
    Verify that inspect_link raises a ValueError for loopback URLs.
    """
    loopbacks = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254"
    ]
    for url in loopbacks:
        # Should raise ValueError due to IP validation blocking or DNS resolution blocking loopbacks
        with pytest.raises(ValueError, match="Unsafe IP address blocked|DNS resolution returned no valid addresses"):
            await inspect_link(url)
