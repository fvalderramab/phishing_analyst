import re
import socket
import logging
import ipaddress
import unicodedata
from urllib.parse import urlparse, urlunparse, urljoin
from typing import List, Optional, Tuple

import httpx
from app.security.deduplicator import sanitize_log_input

# Set up logging for link inspection events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Standard robust regular expression for extracting HTTP/HTTPS URLs from text
URL_REGEX = re.compile(
    r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', re.IGNORECASE
)

# Custom restricted networks for extra security coverage
NAT64_NET = ipaddress.ip_network("64:ff9b::/96")
SIXTOFOUR_NET = ipaddress.ip_network("2002::/16")
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

def extract_urls(text: str) -> list[str]:
    """
    Extracts all URLs from text and normalizes them using Unicode NFC form
    to prevent evasion bypasses.
    """
    if not text:
        return []

    # Normalize character representation canonically (NFC)
    normalized_text = unicodedata.normalize("NFC", text)
    matches = URL_REGEX.findall(normalized_text)

    extracted_urls = []
    for match in matches:
        # Prepend scheme for www. shorthand to form valid URL structure
        if match.lower().startswith("www."):
            match = "http://" + match
        extracted_urls.append(match)

    return extracted_urls

def validate_url_scheme(url: str) -> str:
    """
    Validates that the scheme of the URL is strictly HTTP or HTTPS.
    Raises ValueError for forbidden schemes like file://, ftp://, etc.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Forbidden URL scheme: {scheme}")
    return scheme

def get_all_ips(host: str) -> list[str]:
    """
    Resolves host name to all associated IPv4 and IPv6 addresses using double-stack getaddrinfo.
    """
    if not host:
        return []
    try:
        # Resolve all IPs for the host under any socket type
        addr_info = socket.getaddrinfo(host, None)
        ips = {entry[4][0] for entry in addr_info}
        return list(ips)
    except Exception as err:
        safe_host = sanitize_log_input(host)
        logger.error(f"DNS resolution failed for host {safe_host}: {err}")
        return []

def is_unsafe_ip(ip_str: str) -> bool:
    """
    Checks if an IP address belongs to local, private, multicast, or unspecified spaces.
    Explicitly blocks CGNAT (100.64.0.0/10), NAT64 (64:ff9b::/96), and 6to4 (2002::/16) ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # 1. Check standard private and loopback properties
        if (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified
        ):
            return True

        # 2. Check explicit customized restricted IPv6 and IPv4 networks
        if ip.version == 6:
            if ip in NAT64_NET or ip in SIXTOFOUR_NET:
                return True
        elif ip.version == 4:
            if ip in CGNAT_NET:
                return True

        return False
    except ValueError:
        # Invalid representation is blocked by default
        return True

async def inspect_link(url: str, max_redirects: int = 5) -> httpx.Response:
    """
    Asynchronously inspects a URL by manually tracking redirections up to max_redirects hops.
    Resolves the domain once per hop and connects directly to the validated IP to defeat DNS Rebinding.
    Maps the SNI and Host headers to preserve TLS verification against the IP target.
    """
    # Normalize input
    normalized_url = unicodedata.normalize("NFC", url)
    current_url = normalized_url

    # AsyncClient configured with follow_redirects=False for custom redirect logic
    async with httpx.AsyncClient(follow_redirects=False) as client:
        for hop in range(max_redirects + 1):
            # 1. Scheme Validation
            scheme = validate_url_scheme(current_url)

            parsed = urlparse(current_url)
            host = parsed.hostname
            if not host:
                raise ValueError("URL host is missing or malformed.")

            port = parsed.port

            # 2. Dual-Stack DNS Resolution
            ips = get_all_ips(host)
            if not ips:
                raise ValueError(f"DNS resolution returned no valid addresses for host: {host}")

            # 3. IP Validation (SSRF mitigation)
            for ip in ips:
                if is_unsafe_ip(ip):
                    raise ValueError(f"Unsafe IP address blocked: {ip}")

            # 4. Target IP Selection (DNS Rebinding mitigation)
            # Pick first validated IP
            target_ip = ips[0]

            # 5. URL Reconstruction using the validated IP
            # Wrap IPv6 addresses in brackets for URL format
            netloc = f"[{target_ip}]" if ":" in target_ip else target_ip
            if port:
                netloc = f"{netloc}:{port}"

            ip_parsed = parsed._replace(netloc=netloc)
            ip_url = urlunparse(ip_parsed)

            # Preserve SNI and Host header for SSL connection routing
            headers = {"Host": host}
            extensions = {"sni_hostname": host}

            safe_url = sanitize_log_input(current_url)
            safe_ip = sanitize_log_input(target_ip)
            logger.info(f"Hop {hop}: Fetching {safe_url} via IP {safe_ip} (SNI Host: {sanitize_log_input(host)})")

            try:
                response = await client.request(
                    "GET",
                    ip_url,
                    headers=headers,
                    extensions=extensions,
                    timeout=5.0
                )
            except Exception as err:
                logger.error(f"Request failed at hop {hop} for {safe_url}: {err}")
                raise err

            # 6. Manual Redirect Tracking
            if response.is_redirect:
                if hop >= max_redirects:
                    raise ValueError(f"Maximum redirects limit reached ({max_redirects} hops).")

                location = response.headers.get("Location")
                if not location:
                    raise ValueError("Redirect response did not specify a Location header.")

                # Resolve relative redirect URLs against the current hop's URL
                current_url = urljoin(current_url, location)
                logger.info(f"Hop {hop}: Redirected to {sanitize_log_input(current_url)}")
            else:
                # Successfully reached destination
                return response

    raise ValueError("Request loop terminated without response.")
