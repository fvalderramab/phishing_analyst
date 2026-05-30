import io
import logging
from typing import Literal

import httpx
from PIL import Image
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

from app.config import settings
from app.security.deduplicator import sanitize_log_input

# Set up logging for image processing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityVerdict(BaseModel):
    """
    Structured schema representing the deterministic analysis result from Gemini.
    Strictly avoids Optional/Union types to satisfy Gemini's schema validation,
    utilizing 'Ninguna'/'Ninguno' as string fallbacks, and leverages native list[str].
    """
    veredicto: Literal["seguro", "sospechoso", "phishing"] = Field(
        description="Clasificación estricta de seguridad tras analizar la captura. Debe ser 'seguro', 'sospechoso' o 'phishing'."
    )
    is_phishing: bool = Field(
        description="Indica verdadero si hay indicios razonables de que la captura corresponde a un ataque de phishing o estafa."
    )
    brand_detected: str = Field(
        description="Nombre de la entidad o marca legítima que se intenta suplantar. IMPORTANTE: Si no hay suplantación o marca detectada, debes devolver estrictamente el texto 'Ninguna'."
    )
    extracted_urls: list[str] = Field(
        description="Lista de enlaces, links o URLs sospechosas detectadas textualmente en la captura. Si no hay, devuelve una lista vacía []."
    )
    threat_type: str = Field(
        description="Tipo de amenaza (ej: 'Suplantación bancaria', 'Falso premio', 'Soporte técnico falso'). Si no aplica, devuelve estrictamente 'Ninguno'."
    )
    psychological_manipulation: bool = Field(
        description="Indica verdadero si el mensaje usa urgencia, miedo, o codicia para manipular al usuario."
    )
    risk_analysis: str = Field(
        description="Explicación detallada pero en lenguaje extremadamente simple, amigable y libre de tecnicismos para que un usuario familiar comprenda el peligro de inmediato."
    )

async def download_meta_media(media_id: str) -> bytes:
    """
    Asynchronously queries Meta Graph API to fetch WhatsApp media metadata and
    downloads the binary file, enforcing a strict 7 MB size limit.
    """
    safe_media_id = sanitize_log_input(media_id)
    logger.info(f"Initiating download process for Meta media ID: {safe_media_id}")
    
    metadata_url = f"https://graph.facebook.com/v24.0/{media_id}"
    headers = {"Authorization": f"Bearer {settings.meta_access_token}"}
    
    try:
        async with httpx.AsyncClient() as client:
            # 1. Fetch temporal media download URL
            logger.info(f"Querying Meta Graph API for media URL: {safe_media_id}")
            meta_response = await client.get(metadata_url, headers=headers, timeout=10.0)
            meta_response.raise_for_status()
            metadata = meta_response.json()
            
            download_url = metadata.get("url")
            if not download_url:
                raise ValueError("Temporal download URL not present in Meta response metadata.")
                
            # 2. Download binary media stream
            logger.info(f"Downloading binary media stream for media ID: {safe_media_id}")
            download_response = await client.get(download_url, headers=headers, timeout=15.0)
            download_response.raise_for_status()
            image_bytes = download_response.content
            
            # 3. Strictly validate payload size limit (7 MB = 7340032 bytes)
            max_size_bytes = 7 * 1024 * 1024
            actual_size = len(image_bytes)
            if actual_size > max_size_bytes:
                raise ValueError(
                    f"Downloaded media size exceeds the maximum allowed limit of 7 MB (actual: {actual_size} bytes)."
                )
                
            logger.info(f"Successfully downloaded Meta media {safe_media_id} (size: {actual_size} bytes)")
            return image_bytes
            
    except Exception as err:
        logger.error(f"Failed to download media for ID {safe_media_id}: {err}")
        raise err

async def analyze_screenshot(image_bytes: bytes) -> SecurityVerdict:
    """
    Asynchronously processes the screenshot image bytes in memory:
    1. Loads the image using PIL, validating legibility.
    2. Scaling proportionally using LANCZOS if the longest dimension exceeds 1200px.
    3. Runs multimodal vision inference using Google GenAI SDK asynchronously (gemini-2.5-flash)
       enforcing a strict structured output schema with temperature 0.0.
    """
    logger.info("Initializing screenshot analysis...")
    
    # 1. Load image and check for corruption
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()  # Read pixel data to ensure it's not corrupt
    except Exception as err:
        logger.error(f"Image validation failed (file might be corrupt): {err}")
        raise ValueError(f"Corrupted or invalid image: {err}")
        
    # 2. Proportional Aspect-Ratio downscaling (max 1200px on longest side)
    width, height = image.size
    max_dim = max(width, height)
    if max_dim > 1200:
        scale = 1200.0 / max_dim
        new_width = int(width * scale)
        new_height = int(height * scale)
        image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        logger.info(f"Image optimized. Resized from {width}x{height} to {new_width}x{new_height}")
    else:
        logger.info(f"Image within optimal boundaries: {width}x{height}")

    # 3. Google GenAI Multimodal Vision Inferences
    logger.info("Connecting asynchronously to Google GenAI API...")
    try:
        # Instantiate the official client using configured GEMINI_API_KEY
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # expert cybersecurity vision prompt
        expert_prompt = (
            "Eres un analista experto de ciberseguridad especializado en proteger familias contra ataques de phishing, "
            "estafas y manipulación psicológica. Analiza detalladamente la captura de pantalla provista para identificar:\n"
            "1. Elementos visuales fraudulentos (logos robados, imitación de marcas conocidas).\n"
            "2. Enlaces, links, números telefónicos o URLs sospechosas mostradas en el texto de la captura.\n"
            "3. Indicadores de manipulación psicológica (urgencia, alarmismo, solicitud de claves, amenazas de bloqueo, ofertas sospechosas).\n"
            "4. Errores gramaticales o de diseño que revelen suplantación.\n\n"
            "IMPORTANTE: Proporciona tu veredicto de seguridad estructurado en formato JSON estrictamente siguiendo el esquema Pydantic.\n"
            "El análisis de riesgo ('risk_analysis') debe estar redactado en un español extremadamente simple, cercano, "
            "afectuoso y libre de tecnicismos complejos para que tu abuelo, abuela o tíos entiendan el peligro inmediatamente."
        )
        
        # Structured Output Configuration with explicit safety settings (CWE-1188)
        sdk_config = types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=SecurityVerdict,
            temperature=0.0,  # Enforces schema constraints and string fallbacks deterministically
            safety_settings=[
                types.SafetySetting(
                    category="HARM_CATEGORY_HATE_SPEECH",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_HARASSMENT",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold="BLOCK_MEDIUM_AND_ABOVE",
                ),
            ]
        )
        
        # Async invocation prevents blocking the FastAPI thread loop
        generate_func = getattr(client.aio.models, "generate_content")
        response = await generate_func(
            model=settings.gemini_model,
            contents=[image, expert_prompt],
            config=sdk_config
        )
        
        # Access automatically parsed Pydantic structured output
        verdict: SecurityVerdict = response.parsed
        if not verdict:
            raise ValueError("Gemini returned an empty structured parsed verdict.")
            
        logger.info(f"Screenshot analysis completed. Verdict compiled: {verdict.veredicto}")
        return verdict
        
    except Exception as err:
        logger.error(f"Gemini API vision inference failed: {err}")
        raise err
