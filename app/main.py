import hashlib
import hmac
import json
import logging
import secrets
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Query, HTTPException, BackgroundTasks, status
from fastapi.responses import PlainTextResponse, Response
from redis.asyncio import Redis

from app.config import settings
from app.security.deduplicator import EventDeduplicator
from app.security.utils import sanitize_log_input
from app.services.orchestrator import process_whatsapp_event_task

# Initialize logging for webhook events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global Redis client instance
redis_client: Optional[Redis] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the lifecycle of the FastAPI application, initializing the Redis
    client connection on startup and closing it gracefully on shutdown.
    """
    global redis_client
    logger.info("Initializing connection to Redis...")
    try:
        redis_client = Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            decode_responses=True
        )
        # Test connection health
        await redis_client.ping()
        logger.info("Connected to Redis successfully.")
    except Exception as err:
        logger.error(f"Redis initialization failed! Error: {err}")
        # Lifespan fail-safe: allow server startup even if Redis is unreachable
        redis_client = None

    yield

    if redis_client:
        logger.info("Closing Redis connection pool...")
        await redis_client.aclose()
        logger.info("Redis connection closed securely.")

app = FastAPI(
    title="Phishing Analyst Agent - Base Webhook Server",
    description="FastAPI Server for receiving and processing Meta WhatsApp Cloud API webhooks.",
    version="1.0.0",
    lifespan=lifespan,
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

def extract_message_info(payload: dict) -> tuple[Optional[str], Optional[int]]:
    """
    Extracts the message ID and timestamp from the WhatsApp Cloud API payload.
    Supports both incoming messages (messages) and status updates (statuses),
    safely handling missing keys or indices to avoid exceptions.
    Returns:
        (message_id, timestamp_int)
    """
    try:
        entries = payload.get("entry", [])
        if not entries:
            return None, None
            
        changes = entries[0].get("changes", [])
        if not changes:
            return None, None
            
        value = changes[0].get("value", {})
        
        # 1. Attempt to extract from incoming messages list
        messages = value.get("messages", [])
        if messages:
            msg = messages[0]
            msg_id = msg.get("id")
            ts_str = msg.get("timestamp")
            ts = int(ts_str) if ts_str is not None else None
            return msg_id, ts
            
        # 2. Attempt to extract from status updates list
        statuses = value.get("statuses", [])
        if statuses:
            status_item = statuses[0]
            msg_id = status_item.get("id")
            ts_str = status_item.get("timestamp")
            ts = int(ts_str) if ts_str is not None else None
            return msg_id, ts
            
        return None, None
    except (IndexError, ValueError, TypeError, AttributeError) as err:
        logger.debug(f"Parsing WhatsApp payload failed or was not a message/status event: {err}")
        return None, None

async def process_whatsapp_payload(payload: dict, message_id: Optional[str], timestamp: Optional[int]) -> None:
    """
    Background worker task to process the WhatsApp payload without holding the HTTP response.
    Passes message_id and timestamp consistently to prevent time-drift.
    """
    safe_msg_id = sanitize_log_input(message_id) if message_id else "N/A"
    logger.info(f"Executing background processing of WhatsApp payload for msg_id: {safe_msg_id} (timestamp: {timestamp})...")
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
    Performs signature checks, checks event deduplication, schedules background
    processing, and returns 200 OK immediately to avoid Meta retries.
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

    # Safe payload parsing for both messages and statuses
    message_id, timestamp = extract_message_info(payload)

    # Webhook Event Deduplication with Redis (fail-safe enabled)
    if message_id:
        is_dup = False
        if redis_client is not None:
            deduplicator = EventDeduplicator(redis_client)
            is_dup = await deduplicator.is_duplicate(message_id)
        else:
            logger.warning("Redis client is uninitialized. Skipping deduplication checks (fail-safe mode active).")
            
        if is_dup:
            # Return 200 OK immediately without queuing background task
            return Response(status_code=status.HTTP_200_OK)

    # Offload processing to our services orchestrator background task
    background_tasks.add_task(process_whatsapp_event_task, payload)

    return Response(status_code=status.HTTP_200_OK)
