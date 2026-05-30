import logging
import phonenumbers
import httpx
from app.config import settings
from app.security.utils import sanitize_log_input

# Set up logging for WhatsApp sending operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def format_phone_e164(phone_str: str) -> str:
    """
    Validates and formats the phone number to standard E.164, then strips out
    the '+', '-', and spaces to meet Meta's strict digit-only schema requirements.
    Falls back to basic digit cleaning if parsing fails.
    """
    cleaned = phone_str.strip()
    # Prepend '+' if missing and does not start with international '00' to assist parsing
    if not cleaned.startswith("+") and not cleaned.startswith("00"):
        cleaned = "+" + cleaned

    try:
        parsed = phonenumbers.parse(cleaned, None)
        if not phonenumbers.is_valid_number(parsed):
            raise ValueError("Invalid phone number.")
        formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception as err:
        # Fallback: clean all non-digit characters from the original string
        logger.warning(
            f"phonenumbers parsing failed for {sanitize_log_input(phone_str)}. "
            f"Error: {err}. Falling back to manual digit extraction."
        )
        formatted = "".join(c for c in phone_str if c.isdigit())
        if not formatted:
            raise ValueError(f"No digit characters could be extracted from phone: {phone_str}")
        return formatted

    # Clean character markers for Meta compatibility
    return formatted.replace("+", "").replace("-", "").replace(" ", "")

async def send_whatsapp_message(to_phone: str, text: str) -> bool:
    """
    Asynchronously dispatches a WhatsApp text message to the specified recipient
    using Meta Cloud's Graph API.
    """
    safe_to_phone = sanitize_log_input(to_phone)
    logger.info(f"Preparing to send WhatsApp message to {safe_to_phone}")
    
    try:
        recipient_id = format_phone_e164(to_phone)
    except Exception as err:
        logger.error(f"Failed to format recipient phone number {safe_to_phone}: {err}")
        return False
        
    endpoint = f"https://graph.facebook.com/{settings.meta_api_version}/{settings.whatsapp_phone_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {settings.meta_access_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": recipient_id,
        "type": "text",
        "text": {
            "preview_url": False,
            "body": text
        }
    }
    
    try:
        async with httpx.AsyncClient() as client:
            logger.info(f"Dispatching POST request to Meta endpoint: {endpoint}")
            response = await client.post(endpoint, json=payload, headers=headers, timeout=12.0)
            
            if response.status_code in (200, 201):
                logger.info(f"WhatsApp message successfully delivered to {recipient_id}")
                return True
                
            response_body = response.text
            logger.error(
                f"Meta API rejected message delivery (status: {response.status_code}). "
                f"Response body: {sanitize_log_input(response_body)}"
            )
            return False
            
    except Exception as err:
        logger.error(f"Outbound HTTP request to Meta API failed for recipient {recipient_id}: {err}")
        return False
