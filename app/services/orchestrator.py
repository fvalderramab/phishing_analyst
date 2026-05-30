import logging
import asyncio
import json
from typing import Dict, Any, List

from google import genai
from google.genai import types
from app.config import settings
from app.media.image_processor import download_meta_media, analyze_screenshot, SecurityVerdict
from app.media.whatsapp_sender import send_whatsapp_message
from app.security.link_inspector import extract_urls, inspect_link
from app.security.reputation import run_full_reputation_analysis
from app.security.utils import sanitize_log_input

# Set up logging for the orchestrator service
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def analyze_url_safely(url: str) -> Dict[str, Any]:
    """
    Helper function to inspect a link against SSRF/DNS Rebinding, and if safe,
    retrieve threat intelligence reputation report in parallel.
    """
    safe_url = sanitize_log_input(url)
    logger.info(f"Orchestrator: Safely checking reputation of URL: {safe_url}")
    try:
        # Mitigate SSRF/DNS Rebinding by resolving host and checking IPs first
        await inspect_link(url)
        # If safe to query, perform parallel reputational check
        return await run_full_reputation_analysis(url)
    except Exception as e:
        logger.warning(f"URL inspection blocked or failed for {safe_url}: {e}")
        # Return a compiled dangerous/unsafe fallback block report
        return {
            "url": url,
            "google_safe_browsing": {"is_malicious": True, "error": str(e)},
            "virustotal": {"malicious": 1, "error": str(e)},
            "urlscan": {"is_malicious": True, "error": str(e)},
            "phishtank": {"in_database": True, "verified": True, "error": str(e)},
            "overall_malicious": True,
            "blocked_by_inspector": True,
            "inspection_error": str(e)
        }

async def process_whatsapp_event_task(payload: dict) -> None:
    """
    Main orchestrator task designed to process WhatsApp Cloud API webhook events
    in the background. Routes text and image events asynchronously to cybersecurity
    detection layers, and dispatches warm, Spanish-friendly results back to users.
    """
    sender_phone = "N/A"
    try:
        # 1. Parse incoming payload safely
        entries = payload.get("entry", [])
        if not entries:
            logger.info("WhatsApp payload entry list is empty. Ignoring event.")
            return
            
        changes = entries[0].get("changes", [])
        if not changes:
            logger.info("WhatsApp payload entry changes list is empty. Ignoring event.")
            return
            
        value = changes[0].get("value", {})
        messages = value.get("messages", [])
        if not messages:
            logger.info("WhatsApp event does not contain standard incoming messages list (status/other). Ignoring.")
            return
            
        msg = messages[0]
        sender_phone = msg.get("from")
        if not sender_phone:
            logger.warning("No sender phone number ('from') present in message payload. Aborting.")
            return
            
        safe_phone = sanitize_log_input(sender_phone)
        msg_type = msg.get("type")
        
        logger.info(f"Incoming event processed from user {safe_phone} (type: {msg_type})")
        
        # 2. Setup Gemini Client with safety configurations to satisfy CWE-1188
        client = genai.Client(api_key=settings.gemini_api_key)
        safety_settings = [
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
        sdk_config = types.GenerateContentConfig(
            temperature=0.3,
            safety_settings=safety_settings
        )
        generate_func = getattr(client.aio.models, "generate_content")
        
        # --- FLOW 1: Screenshot Analysis (IMAGE) ---
        if msg_type == "image":
            media_id = msg.get("image", {}).get("id")
            if not media_id:
                logger.error("WhatsApp image message missing required media ID.")
                await send_whatsapp_message(
                    sender_phone,
                    "⚠️ Lo siento, no pudimos procesar la imagen enviada porque no tiene un identificador válido."
                )
                return
                
            logger.info(f"Flow 1: Downloading and processing media ID {sanitize_log_input(media_id)}")
            # Download and analyze screenshot
            image_bytes = await download_meta_media(media_id)
            verdict: SecurityVerdict = await analyze_screenshot(image_bytes)
            
            # Format friendly spanish verdict message with visual semaphores
            emoji = "🟢"
            verdict_text = "SEGURO"
            if verdict.veredicto == "sospechoso":
                emoji = "🟡"
                verdict_text = "SOSPECHOSO"
            elif verdict.veredicto == "phishing":
                emoji = "🔴"
                verdict_text = "PELIGROSO / ESTAFA"
                
            brand_detected = verdict.brand_detected if verdict.brand_detected != "Ninguna" else "Ninguna detectada"
            threat_type = verdict.threat_type if verdict.threat_type != "Ninguno" else "Ninguno detectado"
            psych_manipulation = "Sí" if verdict.psychological_manipulation else "No"
            
            friendly_message = (
                f"¡Hola! He analizado detalladamente la captura de pantalla que me enviaste. "
                f"Aquí tienes mi veredicto de seguridad para tu tranquilidad:\n\n"
                f"🛡️ **Veredicto:** {emoji} {verdict_text}\n"
                f"🏷️ **Marca suplantada:** {brand_detected}\n"
                f"⚠️ **Tipo de amenaza:** {threat_type}\n"
                f"🧠 **Manipulación emocional/urgencia:** {psych_manipulation}\n"
                f"🔗 **Enlaces detectados:** {', '.join(verdict.extracted_urls) if verdict.extracted_urls else 'Ninguno'}\n\n"
                f"💡 **Explicación sencilla:**\n"
                f"{verdict.risk_analysis}"
            )
            
            await send_whatsapp_message(sender_phone, friendly_message)
            return

        # --- FLOW 2: Text Analysis (TEXT) ---
        elif msg_type == "text":
            text_body = msg.get("text", {}).get("body", "")
            if not text_body.strip():
                logger.info("Empty text message body received. Skipping.")
                return
                
            # Extract URLs from body text
            urls = extract_urls(text_body)
            
            # --- Flow 2 - Caso A: Message contains links ---
            if urls:
                logger.info(f"Flow 2 - Caso A: Processing {len(urls)} URLs in parallel...")
                
                # Check link inspections & reputations in parallel
                tasks = [analyze_url_safely(url) for url in urls]
                # Enforce return_exceptions=True for fault tolerance
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Clean exceptions out of results
                clean_results = []
                for index, res in enumerate(results):
                    if isinstance(res, Exception):
                        url_failed = urls[index]
                        logger.error(f"Reputation gather encountered exception for {sanitize_log_input(url_failed)}: {res}")
                        clean_results.append({
                            "url": url_failed,
                            "google_safe_browsing": {"is_malicious": False, "error": str(res)},
                            "virustotal": {"malicious": 0, "error": str(res)},
                            "urlscan": {"is_malicious": False, "error": str(res)},
                            "phishtank": {"in_database": False, "verified": False, "error": str(res)},
                            "overall_malicious": True,
                            "error": str(res)
                        })
                    else:
                        clean_results.append(res)
                        
                # Ask Gemini to compile results in conversational friendly Spanish
                prompt = (
                    "Actúa como un experto analista de ciberseguridad familiar que explica las amenazas de forma cercana, "
                    "afectuosa, extremadamente simple y sin usar tecnicismos complejos para que lo entienda un familiar adulto mayor.\n\n"
                    f"El usuario envió un mensaje que contiene los siguientes enlaces sospechosos:\n"
                    f"Mensaje original: '{text_body}'\n\n"
                    "Hemos ejecutado múltiples análisis técnicos de reputación (Google Safe Browsing, VirusTotal, URLScan, PhishTank) "
                    "y mitigaciones avanzadas contra ataques SSRF y hosts maliciosos. Aquí tienes los resultados agregados en JSON:\n"
                    f"{json.dumps(clean_results, indent=2)}\n\n"
                    "Por favor, compila un veredicto de seguridad amigable. Evalúa cada enlace individualmente utilizando "
                    "semáforos visuales (🟢 Seguro, 🟡 Sospechoso, 🔴 Peligroso). Explica de forma clara e intuitiva qué es lo que "
                    "está mal o por qué es seguro, y bríndales consejos de protección afectuosos en español."
                )
                
                response = await generate_func(
                    model=settings.gemini_model,
                    contents=[prompt],
                    config=sdk_config
                )
                
                compiled_response = response.text
                if not compiled_response:
                    raise ValueError("Gemini returned empty text response during url threat compilation.")
                    
                await send_whatsapp_message(sender_phone, compiled_response)
                return

            # --- Flow 2 - Caso B: Conversational text message (no links) ---
            else:
                logger.info("Flow 2 - Caso B: No URLs detected. Consulting Gemini conversationally...")
                prompt = (
                    "Eres un consultor experto de seguridad familiar interactivo. Responde de forma cálida, cercana, amigable "
                    "y en un español muy sencillo, libre de tecnicismos complejos. El usuario te ha enviado un mensaje "
                    "para que evalúes si es un engaño (como phishing, solicitudes falsas de contraseñas, premios irreales, "
                    "bloqueos bancarios de urgencia, soporte técnico fraudulento, etc.).\n\n"
                    f"Mensaje del usuario: '{text_body}'\n\n"
                    "Analiza el texto buscando técnicas comunes de ingeniería social, manipulación psicológica, pánico o codicia. "
                    "Dale un veredicto intuitivo y ofrécele consejos de seguridad rápidos y muy afectuosos para protegerse."
                )
                
                response = await generate_func(
                    model=settings.gemini_model,
                    contents=[prompt],
                    config=sdk_config
                )
                
                compiled_response = response.text
                if not compiled_response:
                    raise ValueError("Gemini returned empty conversational consultation response.")
                    
                await send_whatsapp_message(sender_phone, compiled_response)
                return
                
        else:
            logger.info(f"WhatsApp message type {msg_type} is not supported. Ignoring.")
            return
            
    except Exception as err:
        safe_phone = sanitize_log_input(sender_phone)
        logger.error(f"Error executing orchestrator background worker for user {safe_phone}: {err}")
        # Fail-Safe Delivery: Dispatch automated apology message to prevent hanging or silent drops
        if sender_phone != "N/A":
            apology_text = (
                "⚠️ Lo siento, ocurrió un error técnico al analizar tu mensaje. "
                "Por favor, vuelve a intentarlo en unos minutos."
            )
            await send_whatsapp_message(sender_phone, apology_text)
