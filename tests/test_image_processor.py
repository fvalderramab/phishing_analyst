import io
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from PIL import Image

from app.media.image_processor import (
    SecurityVerdict,
    download_meta_media,
    analyze_screenshot
)

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_download_meta_media_success(mock_get):
    """
    Verify that download_meta_media successfully queries the Graph API metadata
    and downloads the binary image content.
    """
    # 1. Mock Graph API metadata response
    mock_metadata_resp = MagicMock()
    mock_metadata_resp.status_code = 200
    mock_metadata_resp.json.return_value = {
        "url": "https://lookaside.fbsbx.com/mock_media_url_123",
        "mime_type": "image/png"
    }
    
    # 2. Mock temporal binary download response
    mock_binary_resp = MagicMock()
    mock_binary_resp.status_code = 200
    mock_binary_resp.content = b"fake-png-binary-stream-data"
    
    # Configure the client GET mock to return metadata first, then binary content
    mock_get.side_effect = [mock_metadata_resp, mock_binary_resp]
    
    result_bytes = await download_meta_media("meta_media_id_999")
    assert result_bytes == b"fake-png-binary-stream-data"
    assert mock_get.call_count == 2

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_download_meta_media_size_limit(mock_get):
    """
    Verify that download_meta_media raises a ValueError if the downloaded media
    exceeds the maximum size limit of 7 MB.
    """
    mock_metadata_resp = MagicMock()
    mock_metadata_resp.status_code = 200
    mock_metadata_resp.json.return_value = {
        "url": "https://lookaside.fbsbx.com/mock_media_url_123"
    }
    
    mock_binary_resp = MagicMock()
    mock_binary_resp.status_code = 200
    # Create content that exceeds 7 MB (7 MB + 10 bytes)
    mock_binary_resp.content = b"x" * (7 * 1024 * 1024 + 10)
    
    mock_get.side_effect = [mock_metadata_resp, mock_binary_resp]
    
    with pytest.raises(ValueError, match="exceeds the maximum allowed limit of 7 MB"):
        await download_meta_media("meta_media_id_large")

@pytest.mark.asyncio
async def test_analyze_screenshot_corrupt_bytes():
    """
    Verify that analyze_screenshot raises a ValueError if the input image
    bytes are corrupted or unreadable.
    """
    corrupt_bytes = b"not-a-valid-image-format-bytes"
    with pytest.raises(ValueError, match="Corrupted or invalid image"):
        await analyze_screenshot(corrupt_bytes)

@pytest.mark.asyncio
@patch("google.genai.Client")
async def test_analyze_screenshot_success(mock_client_class):
    """
    Verify that analyze_screenshot successfully loads a valid image,
    submits it to Gemini, and returns a validated SecurityVerdict.
    """
    # 1. Create a minimal valid PNG image in memory
    img = Image.new("RGB", (100, 100), color="blue")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    valid_bytes = img_byte_arr.getvalue()
    
    # 2. Mock Gemini Client and async generate_content
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    mock_response = MagicMock()
    # Mocking parsed output returning our structured Pydantic model
    mock_verdict = SecurityVerdict(
        veredicto="phishing",
        is_phishing=True,
        brand_detected="Netflix",
        extracted_urls=["http://netflix-login-scam.com"],
        threat_type="Suplantación de servicio de streaming",
        psychological_manipulation=True,
        risk_analysis="Te están intentando engañar usando la marca Netflix. No entres al enlace."
    )
    mock_response.parsed = mock_verdict
    
    # Mock Async generate_content
    mock_generate_content = AsyncMock(return_value=mock_response)
    mock_client.aio.models.generate_content = mock_generate_content
    
    result = await analyze_screenshot(valid_bytes)
    
    assert isinstance(result, SecurityVerdict)
    assert result.is_phishing is True
    assert result.veredicto == "phishing"
    assert result.brand_detected == "Netflix"
    assert "http://netflix-login-scam.com" in result.extracted_urls
    
    # Confirm async generate_content was called
    assert mock_generate_content.call_count == 1

@pytest.mark.asyncio
@patch("google.genai.Client")
async def test_analyze_screenshot_downscaling(mock_client_class):
    """
    Verify that analyze_screenshot downscales a large image proportionally
    if its longest dimension exceeds 1200px.
    """
    # Create a large valid image (2000 x 1000 pixels)
    img = Image.new("RGB", (2000, 1000), color="green")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    large_bytes = img_byte_arr.getvalue()
    
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_response = MagicMock()
    mock_response.parsed = SecurityVerdict(
        veredicto="seguro",
        is_phishing=False,
        brand_detected="Ninguna",
        extracted_urls=[],
        threat_type="Ninguno",
        psychological_manipulation=False,
        risk_analysis="La captura está limpia."
    )
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
    
    # Patch PIL Image resize to track arguments and assert LANCZOS resizing
    with patch.object(Image.Image, "resize") as mock_resize:
        # Mock resized image to return a new Image
        mock_resized_image = Image.new("RGB", (1200, 600), color="green")
        mock_resize.return_value = mock_resized_image
        
        await analyze_screenshot(large_bytes)
        
        # Verify resize was called to downscale image
        assert mock_resize.call_count == 1
        # It must resize to 1200 x 600 maintaining 2000:1000 = 2:1 aspect ratio
        mock_resize.assert_called_with((1200, 600), Image.Resampling.LANCZOS)
