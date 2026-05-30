import logging
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

# Set up logging for config operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    """
    Application settings class which loads and validates configuration variables
    from environment variables or a local .env file.
    """
    
    # Meta / WhatsApp Cloud API credentials
    whatsapp_verify_token: str = Field(..., validation_alias="WHATSAPP_VERIFY_TOKEN")
    meta_app_secret: str = Field(..., validation_alias="META_APP_SECRET")
    meta_api_version: str = Field(..., validation_alias="META_API_VERSION")
    whatsapp_phone_number_id: str = Field(..., validation_alias="WHATSAPP_PHONE_NUMBER_ID")
    meta_access_token: str = Field(..., validation_alias="META_ACCESS_TOKEN")
    
    # Gemini AI configuration
    gemini_api_key: str = Field(..., validation_alias="GEMINI_API_KEY")
    gemini_model: str = Field(..., validation_alias="GEMINI_MODEL")
    
    # External Security APIs for Phishing Analysis
    safe_browsing_api_key: str = Field(..., validation_alias="SAFE_BROWSING_API_KEY")
    virustotal_api_key: str = Field(..., validation_alias="VIRUSTOTAL_API_KEY")
    urlscan_api_key: str = Field(..., validation_alias="URLSCAN_API_KEY")
    phishtank_api_key: str = Field(..., validation_alias="PHISHTANK_API_KEY")
    phishtank_user_name: str = Field(..., validation_alias="PHISHTANK_USER_NAME")
    
    # Local Redis Configuration
    redis_host: str = Field("redis", validation_alias="REDIS_HOST")
    redis_port: int = Field(6379, validation_alias="REDIS_PORT")
    redis_db: int = Field(0, validation_alias="REDIS_DB")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

try:
    settings = Settings()
    logger.info("Application settings loaded and validated successfully.")
except Exception as err:
    logger.error("Configuration validation failed! Ensure all variables in .env are correctly configured.")
    raise err
