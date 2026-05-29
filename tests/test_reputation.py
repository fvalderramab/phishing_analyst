import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.security.reputation import (
    get_google_safe_browsing,
    get_virustotal_report,
    get_urlscan_report,
    get_phishtank_report,
    run_full_reputation_analysis
)

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_get_google_safe_browsing_match(mock_post):
    """
    Verify Google Safe Browsing Lookup connector successfully identifies
    threat matches in response JSON.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "http://malicious-site.com"}
            }
        ]
    }
    mock_post.return_value = mock_response

    result = await get_google_safe_browsing("http://malicious-site.com")
    assert result["is_malicious"] is True
    assert len(result["matches"]) == 1
    assert result["matches"][0]["threatType"] == "SOCIAL_ENGINEERING"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_get_google_safe_browsing_clean(mock_post):
    """
    Verify Google Safe Browsing Lookup connector returns clean check
    when response matches is empty.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_post.return_value = mock_response

    result = await get_google_safe_browsing("http://safe-site.com")
    assert result["is_malicious"] is False

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_get_virustotal_report_malicious(mock_get):
    """
    Verify VirusTotal connector fetches attributes and last analysis stats.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 8,
                    "suspicious": 2,
                    "malicious": 4,
                    "undetected": 40
                }
            }
        }
    }
    mock_get.return_value = mock_response

    result = await get_virustotal_report("http://malicious.com")
    assert result["malicious"] == 4
    assert result["suspicious"] == 2
    assert result["harmless"] == 8

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_get_urlscan_report_clean(mock_get):
    """
    Verify URLScan connector returns clean if matches have no malicious overall verdict.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {
                "page": {"url": "http://example.com"},
                "verdicts": {
                    "overall": {
                        "malicious": False
                    }
                }
            }
        ]
    }
    mock_get.return_value = mock_response

    result = await get_urlscan_report("http://example.com")
    assert result["is_malicious"] is False

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_get_phishtank_report_normalization(mock_post):
    """
    Verify PhishTank connector normalizes verified strings 'yes'/'y' to boolean True.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": {
            "in_database": True,
            "verified": "yes"
        }
    }
    mock_post.return_value = mock_response

    result = await get_phishtank_report("http://phishing-site.net")
    assert result["in_database"] is True
    assert result["verified"] is True

@pytest.mark.asyncio
@patch("app.main.redis_client", new=None)  # Mock Redis offline to verify fail-safe
@patch("app.security.reputation.get_google_safe_browsing")
@patch("app.security.reputation.get_virustotal_report")
@patch("app.security.reputation.get_urlscan_report")
@patch("app.security.reputation.get_phishtank_report")
async def test_run_full_reputation_analysis_orchestrator(
    mock_phishtank, mock_urlscan, mock_virustotal, mock_safebrowsing
):
    """
    Verify run_full_reputation_analysis gathers parallel results,
    computes the unified malicious decision, and manages exceptions cleanly.
    """
    # 1. Mocking clean results
    mock_safebrowsing.return_value = {"is_malicious": False, "matches": []}
    mock_virustotal.return_value = {"harmless": 10, "suspicious": 0, "malicious": 0}
    mock_urlscan.return_value = {"is_malicious": False}
    
    # Mocking PhishTank failure (returns an Exception to test individual exception recovery)
    mock_phishtank.side_effect = Exception("PhishTank API Timeout")

    result = await run_full_reputation_analysis("http://example.com")
    
    # Verify overall result compiles successfully instead of crashing due to PhishTank's exception
    assert result["overall_malicious"] is False
    assert result["google_safe_browsing"]["is_malicious"] is False
    assert result["virustotal"]["malicious"] == 0
    
    # Confirm PhishTank exception was caught, logging an error and falling back cleanly
    assert result["phishtank"]["verified"] is False
    assert "PhishTank API Timeout" in result["phishtank"]["error"]
