import hashlib
import hmac
import json
import logging
import secrets

from fastapi import FastAPI, Request, Query, HTTPException, BackgroundTasks, status
from fastapi.responses import PlainTextResponse, Response

from app.config import settings

# Initialize logging for webhook events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sanitize_log_input(value: str) -> str:
    """
    Sanitize user input before logging to prevent log injection (CWE-117).
    Replaces carriage returns and line feeds with their escaped representations.
    """
    if not isinstance(value, str):
        return str(value)
    return value.replace("\n", "\\n").replace("\r", "\\r")

app = FastAPI(
    title="Phishing Analyst Agent - Base Webhook Server",
    description="FastAPI Server for receiving and processing Meta WhatsApp Cloud API webhooks.",
    version="1.0.0",
)

async def verify_signature(request: Request) -> bytes:
    """
    Verify that the request payload is authentic by calculating the SHA256 HMAC
    with META_APP_SECRET and comparing it against the X-Hub-Signature-256 header.
    """
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        logger.warning("Missing X-Hub-Signature-256 header in request.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature header missing."
        )

    # Meta signature header format is: sha256=HEX_SIGNATURE
    if not signature_header.startswith("sha256="):
        logger.warning("Malformed X-Hub-Signature-256 header.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed signature header format."
        )

    expected_signature = signature_header.split("sha256=")[1]
    raw_body = await request.body()

    # Calculate HMAC-SHA256 on raw body
    computed_signature = hmac.new(
        key=settings.meta_app_secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    # Avoid timing attacks during verification
    if not secrets.compare_digest(expected_signature, computed_signature):
        logger.error("HMAC signature verification failed! Possible request tampering.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid payload signature."
        )

    return raw_body

async def process_whatsapp_payload(payload: dict) -> None:
    """
    Background worker task to process the WhatsApp payload without holding the HTTP response.
    """
    logger.info("Executing background processing of WhatsApp payload...")
    try:
        # Placeholder for routing content to phishing engine, redis caching, and Gemini API
        logger.info(f"Incoming payload contents parsed: {json.dumps(payload, indent=2)}")
    except Exception as err:
        logger.error(f"Error executing background task: {err}")

@app.get("/")
def read_root():
    """
    Health check endpoint.
    """
    return {
        "status": "online",
        "service": "Familiar Phishing Analyst Agent Base",
        "version": "1.0.0"
    }

@app.get("/webhook", response_class=PlainTextResponse)
def verify_webhook(
    hub_mode: str = Query(..., alias="hub.mode"),
    hub_verify_token: str = Query(..., alias="hub.verify_token"),
    hub_challenge: str = Query(..., alias="hub.challenge"),
):
    """
    Verify webhook endpoint called by Meta when setting up or changing subscription.
    Compares the challenge verify token against configured WHATSAPP_VERIFY_TOKEN.
    """
    if hub_mode != "subscribe":
        logger.warning(f"Invalid webhook subscription mode received: {sanitize_log_input(hub_mode)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hub.mode."
        )

    # Use compare_digest to prevent potential timing-based information leaks
    if not secrets.compare_digest(hub_verify_token, settings.whatsapp_verify_token):
        logger.error("Webhook verify token verification failed.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verification token mismatch."
        )

    logger.info("Webhook successfully verified by Meta.")
    return hub_challenge

@app.post("/webhook")
async def receive_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Receive payloads representing events from the WhatsApp Cloud API.
    Performs signature checks, schedules background processing, and returns 200 OK immediately.
    """
    # Enforce request authenticity before processing
    raw_body = await verify_signature(request)

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except UnicodeDecodeError as decode_err:
        logger.error(f"Decoding request body failed: {decode_err}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Encoding error."
        )
    except json.JSONDecodeError as json_err:
        logger.error(f"Failed to parse payload: {json_err}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON."
        )

    # Offload processing to a background task to return a 200 response immediately to Meta
    background_tasks.add_task(process_whatsapp_payload, payload)

    return Response(status_code=status.HTTP_200_OK)
