import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.media.whatsapp_sender import format_phone_e164, send_whatsapp_message
from app.services.orchestrator import process_whatsapp_event_task, analyze_url_safely
from app.media.image_processor import SecurityVerdict
from app.config import settings

# --- Unit Tests: whatsapp_sender ---

def test_format_phone_e164_valid():
    """
    Verify that format_phone_e164 successfully formats valid international numbers
    and cleans out all formatting character markers like +, -, and spaces.
    """
    # Clean standard international format
    assert format_phone_e164("+1 (650) 555-1234") == "16505551234"
    # Number with hyphens and spaces without + (will prepend + to parse E.164)
    assert format_phone_e164("52 1 55 1234 5678") == "525512345678"

def test_format_phone_e164_fallback():
    """
    Verify that if phonenumbers library fails to parse, it falls back to raw digits extraction.
    """
    # Bad formatting, but has digits
    assert format_phone_e164("abcd-12345-efgh") == "12345"
    
    # Exception case: no digits at all
    with pytest.raises(ValueError, match="No digit characters could be extracted"):
        format_phone_e164("no_digits_here")

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_send_whatsapp_message_success(mock_post):
    """
    Verify that send_whatsapp_message hits the dynamically-defined Meta endpoint
    with correct headers and payload and returns True on success.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    success = await send_whatsapp_message("+16505551234", "Hola Familia")
    assert success is True
    
    # Assert Meta endpoint construction
    expected_endpoint = f"https://graph.facebook.com/{settings.meta_api_version}/{settings.whatsapp_phone_number_id}/messages"
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == expected_endpoint
    assert kwargs["headers"]["Authorization"] == f"Bearer {settings.meta_access_token}"
    assert kwargs["json"]["to"] == "16505551234"
    assert kwargs["json"]["text"]["body"] == "Hola Familia"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_send_whatsapp_message_failure(mock_post):
    """
    Verify that send_whatsapp_message handles API errors gracefully and returns False.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = "Bad Request from Meta"
    mock_post.return_value = mock_resp

    success = await send_whatsapp_message("+16505551234", "Hola Familia")
    assert success is False


# --- Unit Tests: Orchestrator Service ---

@pytest.mark.asyncio
@patch("app.services.orchestrator.inspect_link", new_callable=AsyncMock)
@patch("app.services.orchestrator.run_full_reputation_analysis", new_callable=AsyncMock)
async def test_analyze_url_safely_success(mock_reputation, mock_inspect):
    """
    Verify that analyze_url_safely triggers inspect_link first for SSRF mitigation,
    and then fetches parallel reputational check report.
    """
    mock_inspect.return_value = None
    mock_reputation.return_value = {"overall_malicious": False}

    report = await analyze_url_safely("http://safe-link.com")
    assert report["overall_malicious"] is False
    mock_inspect.assert_called_once_with("http://safe-link.com")
    mock_reputation.assert_called_once_with("http://safe-link.com")

@pytest.mark.asyncio
@patch("app.services.orchestrator.inspect_link", new_callable=AsyncMock)
async def test_analyze_url_safely_blocked_ssrf(mock_inspect):
    """
    Verify that analyze_url_safely blocks loopback/private IPs from reaching out-of-band APIs,
    marking them as unsafe immediately.
    """
    mock_inspect.side_effect = ValueError("Unsafe IP address blocked: 127.0.0.1")

    report = await analyze_url_safely("http://127.0.0.1/malicious")
    assert report["overall_malicious"] is True
    assert report["blocked_by_inspector"] is True
    assert "Unsafe IP address blocked" in report["inspection_error"]

@pytest.mark.asyncio
@patch("app.services.orchestrator.download_meta_media", new_callable=AsyncMock)
@patch("app.services.orchestrator.analyze_screenshot", new_callable=AsyncMock)
@patch("app.services.orchestrator.send_whatsapp_message", new_callable=AsyncMock)
async def test_orchestrator_flow_1_image(mock_send, mock_analyze, mock_download):
    """
    Verify that image-type WhatsApp messages trigger the download, downscaling,
    vision analysis, semaphore translation, and friendly Spanish response.
    """
    # Mocking Meta payload
    payload = {
        "entry": [{
            "changes": [{
                "value": {
                    "messages": [{
                        "from": "5215512345678",
                        "type": "image",
                        "image": {"id": "meta_img_id_101"}
                    }]
                }
            }]
        }]
    }

    mock_download.return_value = b"fake-screenshot-bytes"
    mock_verdict = SecurityVerdict(
        veredicto="phishing",
        is_phishing=True,
        brand_detected="Netflix",
        extracted_urls=["http://netflix-scam-url.com"],
        threat_type="Suplantación de marca",
        psychological_manipulation=True,
        risk_analysis="Te quieren robar tu clave fingiendo que es Netflix. No entres al enlace."
    )
    mock_analyze.return_value = mock_verdict
    mock_send.return_value = True

    await process_whatsapp_event_task(payload)

    mock_download.assert_called_once_with("meta_img_id_101")
    mock_analyze.assert_called_once_with(b"fake-screenshot-bytes")
    
    # Confirm friendly outbound WhatsApp is sent
    mock_send.assert_called_once()
    args, kwargs = mock_send.call_args
    assert args[0] == "5215512345678"
    assert "🔴 PELIGROSO" in args[1]
    assert "Netflix" in args[1]
    assert "Te quieren robar tu clave" in args[1]

@pytest.mark.asyncio
@patch("app.services.orchestrator.analyze_url_safely", new_callable=AsyncMock)
@patch("google.genai.Client")
@patch("app.services.orchestrator.send_whatsapp_message", new_callable=AsyncMock)
async def test_orchestrator_flow_2_text_with_links(mock_send, mock_client_class, mock_analyze_url):
    """
    Verify Flow 2 - Caso A: A text message with links triggers parallel reputational analysis
    and feeds threat findings to Gemini to compile a friendly Spanish warning message.
    """
    payload = {
        "entry": [{
            "changes": [{
                "value": {
                    "messages": [{
                        "from": "5215512345678",
                        "type": "text",
                        "text": {"body": "Mira esto urgente: http://banco-login-scam.com"}
                    }]
                }
            }]
        }]
    }

    # Parallel URL analyze returns reputational result
    mock_analyze_url.return_value = {
        "url": "http://banco-login-scam.com",
        "overall_malicious": True,
        "phishtank": {"verified": True}
    }

    # Mock Gemini Content Generation
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_response = MagicMock()
    mock_response.text = "⚠️ Alerta Familiar: Ese enlace de banco es peligroso, no lo abras."
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

    await process_whatsapp_event_task(payload)

    mock_analyze_url.assert_called_once_with("http://banco-login-scam.com")
    mock_send.assert_called_once_with(
        "5215512345678",
        "⚠️ Alerta Familiar: Ese enlace de banco es peligroso, no lo abras."
    )

@pytest.mark.asyncio
@patch("google.genai.Client")
@patch("app.services.orchestrator.send_whatsapp_message", new_callable=AsyncMock)
async def test_orchestrator_flow_2_text_no_links(mock_send, mock_client_class):
    """
    Verify Flow 2 - Caso B: A text message without links skips reputational checks and
    queries Gemini directly to reply conversationally in a warm Spanish security advisor tone.
    """
    payload = {
        "entry": [{
            "changes": [{
                "value": {
                    "messages": [{
                        "from": "5215512345678",
                        "type": "text",
                        "text": {"body": "Hola, me llegó un mensaje que dice que gané un premio. ¿Es real?"}
                    }]
                }
            }]
        }]
    }

    # Mock Gemini response
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_response = MagicMock()
    mock_response.text = "Hola tío, ese premio de lotería es una estafa muy común. Ten cuidado y no des tus datos."
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

    await process_whatsapp_event_task(payload)

    # Conversational consulting dispatched
    mock_send.assert_called_once_with(
        "5215512345678",
        "Hola tío, ese premio de lotería es una estafa muy común. Ten cuidado y no des tus datos."
    )

@pytest.mark.asyncio
@patch("app.services.orchestrator.download_meta_media", new_callable=AsyncMock)
@patch("app.services.orchestrator.send_whatsapp_message", new_callable=AsyncMock)
async def test_orchestrator_fail_safe_apology(mock_send, mock_download):
    """
    Verify that if any general unexpected exception occurs, the try/except fail-safe
    recovers, logs the issue, and dispatches the standard technical apology WhatsApp.
    """
    payload = {
        "entry": [{
            "changes": [{
                "value": {
                    "messages": [{
                        "from": "5215512345678",
                        "type": "image",
                        "image": {"id": "meta_img_id_101"}
                    }]
                }
            }]
        }]
    }

    # Force a failure
    mock_download.side_effect = ConnectionError("Downstream network disconnected.")

    await process_whatsapp_event_task(payload)

    # Expect apology message was dispatched
    mock_send.assert_called_once_with(
        "5215512345678",
        "⚠️ Lo siento, ocurrió un error técnico al analizar tu mensaje. Por favor, vuelve a intentarlo en unos minutos."
    )
