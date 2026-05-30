import logging
from redis.asyncio import Redis

from app.security.utils import sanitize_log_input

# Initialize logging
logger = logging.getLogger(__name__)

class EventDeduplicator:
    """
    Deduplicates Meta WhatsApp API webhook events by atomically checking and
    setting message/status IDs in Redis using SET EX NX.
    """
    def __init__(self, redis_client: Redis, ttl_seconds: int = 600):
        self.redis = redis_client
        self.ttl = ttl_seconds

    async def is_duplicate(self, message_id: str) -> bool:
        """
        Check if the message_id is a duplicate.
        Returns:
            True if the message_id has already been processed (duplicate).
            False if it's new (unique) or if Redis is unreachable (fail-safe).
        """
        if not message_id:
            return False

        cache_key = f"wa_msg_id:{message_id}"
        safe_msg_id = sanitize_log_input(message_id)

        try:
            # Atomically set key if not exists (NX) with expiration in seconds (EX)
            result = await self.redis.set(cache_key, "1", ex=self.ttl, nx=True)
            if result:
                logger.info(f"Unique event ID registered in Redis: {safe_msg_id}")
                return False  # Brand new unique event
            
            logger.warning(f"Duplicate message detected: {safe_msg_id}. Skipping processing.")
            return True  # Duplicate event
        except Exception as err:
            # Elegant fail-safe: log error and allow message processing to continue
            logger.error(f"Redis deduplicator connection failure (fail-safe mode): {err}")
            return False
