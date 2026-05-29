import base64
import hashlib
import json
import logging
import asyncio
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import httpx
from app.config import settings
from app.security.deduplicator import sanitize_log_input

# Set up logging for reputation analysis
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def get_google_safe_browsing(url: str) -> Dict[str, Any]:
    """
    Asynchronously queries Google Safe Browsing Lookup API (v4) to check if the
    URL is classified as malware, social engineering, or unwanted software.
    """
    api_key = settings.safe_browsing_api_key
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "phishing-analyst-agent",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE", 
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(endpoint, json=payload, timeout=8.0)
            response.raise_for_status()
            data = response.json()
            matches = data.get("matches", [])
            
            is_malicious = len(matches) > 0
            return {
                "is_malicious": is_malicious,
                "matches": matches
            }
    except Exception as err:
        safe_url = sanitize_log_input(url)
        logger.error(f"Google Safe Browsing request failed for {safe_url}: {err}")
        # Return a safe fallback structure
        return {
            "is_malicious": False,
            "matches": [],
            "error": str(err)
        }

async def get_virustotal_report(url: str) -> Dict[str, Any]:
    """
    Asynchronously queries VirusTotal v3 URL Report endpoint by encoding the URL
    to Base64 URL-safe format without padding, avoiding manual re-scans.
    """
    # 1. Base64 URL-safe encoding without trailing padding '='
    encoded_url = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": settings.virustotal_api_key}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(endpoint, headers=headers, timeout=8.0)
            
            if response.status_code == 429:
                logger.warning("VirusTotal API rate limit hit (429).")
                return {
                    "harmless": 0, "suspicious": 0, "malicious": 0, 
                    "error": "Rate limit exceeded (429)"
                }
                
            response.raise_for_status()
            data = response.json()
            
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "harmless": stats.get("harmless", 0),
                "suspicious": stats.get("suspicious", 0),
                "malicious": stats.get("malicious", 0),
                "undetected": stats.get("undetected", 0)
            }
    except Exception as err:
        safe_url = sanitize_log_input(url)
        logger.error(f"VirusTotal request failed for {safe_url}: {err}")
        return {
            "harmless": 0,
            "suspicious": 0,
            "malicious": 0,
            "error": str(err)
        }

async def get_urlscan_report(url: str, max_retries: int = 3) -> Dict[str, Any]:
    """
    Asynchronously searches urlscan.io historical records using domain/URL search.
    Utilizes exponential back-off retries on rate limit (HTTP 429).
    """
    domain = urlparse(url).hostname or ""
    query = f'page.url:"{url}" OR domain:"{domain}"'
    endpoint = f"https://urlscan.io/api/v1/search/?q={query}"
    headers = {"API-Key": settings.urlscan_api_key}
    
    delay = 1.0
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(endpoint, headers=headers, timeout=10.0)
                
                if response.status_code == 429:
                    logger.warning(f"URLScan rate limit hit (429). Attempt {attempt + 1}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                    delay *= 2.0  # Exponential back-off
                    continue
                    
                response.raise_for_status()
                data = response.json()
                
                results = data.get("results", [])
                is_malicious = False
                
                for item in results:
                    verdicts = item.get("verdicts", {})
                    overall = verdicts.get("overall", {})
                    if overall.get("malicious") is True:
                        is_malicious = True
                        break
                        
                return {"is_malicious": is_malicious}
        except Exception as err:
            safe_url = sanitize_log_input(url)
            logger.error(f"URLScan request failed for {safe_url} on attempt {attempt + 1}: {err}")
            if attempt == max_retries - 1:
                return {"is_malicious": False, "error": str(err)}
            await asyncio.sleep(delay)
            delay *= 2.0
            
    return {"is_malicious": False, "error": "Max retries exceeded on HTTP 429"}

async def get_phishtank_report(url: str) -> Dict[str, Any]:
    """
    Asynchronously queries PhishTank checkurl API by sending a Base64-encoded
    URL in an application/x-www-form-urlencoded POST body.
    Normalizes PhishTank's 'verified' parameter to a strict Python boolean.
    """
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    b64_url = base64.b64encode(url.encode("utf-8")).decode("utf-8")
    
    payload = {
        "url": b64_url,
        "format": "json",
        "app_key": settings.phishtank_api_key
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(endpoint, data=payload, timeout=8.0)
            response.raise_for_status()
            data = response.json()
            
            results = data.get("results", {})
            in_database = results.get("in_database", False)
            verified_val = results.get("verified")
            
            # Normalize PhishTank verified string ("yes", "y", "true") to pure boolean
            verified = False
            if isinstance(verified_val, bool):
                verified = verified_val
            elif isinstance(verified_val, str):
                verified = verified_val.lower() in ("yes", "y", "true")
                
            return {
                "in_database": in_database,
                "verified": verified
            }
    except Exception as err:
        safe_url = sanitize_log_input(url)
        logger.error(f"PhishTank request failed for {safe_url}: {err}")
        return {
            "in_database": False,
            "verified": False,
            "error": str(err)
        }

async def run_full_reputation_analysis(url: str) -> Dict[str, Any]:
    """
    Main orchestrator for checking threat intelligence reputation.
    1. Checks the Redis cache first by mapping the SHA-256 hash of the URL.
    2. Runs Google, VirusTotal, URLScan, and PhishTank queries in parallel.
    3. Handles individual API exceptions cleanly to protect workflow execution.
    4. Caches consolidated report in Redis for 24 hours.
    """
    # Import redis_client lazily to avoid any circular dependency at startup
    from app.main import redis_client
    
    # 1. SHA-256 URL Cache Key mapping
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    cache_key = f"url_rep:{url_hash}"
    safe_url = sanitize_log_input(url)
    
    # 2. Query Redis Cache
    if redis_client is not None:
        try:
            cached_data = await redis_client.get(cache_key)
            if cached_data:
                logger.info(f"Cache HIT for URL reputation: {safe_url}")
                return json.loads(cached_data)
        except Exception as cache_err:
            logger.error(f"Redis cache read failure (fail-safe): {cache_err}")
            
    logger.info(f"Cache MISS for URL reputation: {safe_url}. Running parallel threat intelligence checks...")
    
    # 3. Parallel execution with asyncio.gather, return_exceptions=True
    tasks = [
        get_google_safe_browsing(url),
        get_virustotal_report(url),
        get_urlscan_report(url),
        get_phishtank_report(url)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 4. Strict individual exception handling & fallback replacements
    google_res = results[0]
    if isinstance(google_res, Exception):
        logger.error(f"Google Safe Browsing gathered Exception: {google_res}")
        google_res = {"is_malicious": False, "matches": [], "error": str(google_res)}
        
    vt_res = results[1]
    if isinstance(vt_res, Exception):
        logger.error(f"VirusTotal gathered Exception: {vt_res}")
        vt_res = {"harmless": 0, "suspicious": 0, "malicious": 0, "error": str(vt_res)}
        
    urlscan_res = results[2]
    if isinstance(urlscan_res, Exception):
        logger.error(f"URLScan gathered Exception: {urlscan_res}")
        urlscan_res = {"is_malicious": False, "error": str(urlscan_res)}
        
    phish_res = results[3]
    if isinstance(phish_res, Exception):
        logger.error(f"PhishTank gathered Exception: {phish_res}")
        phish_res = {"in_database": False, "verified": False, "error": str(phish_res)}
        
    # 5. Compile Overall Verdict
    overall_malicious = (
        google_res.get("is_malicious", False) or
        vt_res.get("malicious", 0) > 0 or
        urlscan_res.get("is_malicious", False) or
        phish_res.get("verified", False)
    )
    
    compiled_verdict = {
        "url": url,
        "google_safe_browsing": google_res,
        "virustotal": vt_res,
        "urlscan": urlscan_res,
        "phishtank": phish_res,
        "overall_malicious": overall_malicious
    }
    
    # 6. Cache Verdict in Redis (24 hours TTL = 86400s)
    if redis_client is not None:
        try:
            await redis_client.set(cache_key, json.dumps(compiled_verdict), ex=86400)
            logger.info(f"Cache SET completed for URL reputation: {safe_url}")
        except Exception as cache_err:
            logger.error(f"Redis cache write failure (fail-safe): {cache_err}")
            
    return compiled_verdict
