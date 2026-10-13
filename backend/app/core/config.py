"""
app/core/config.py

Purpose:
    Single source of truth for all configuration. Every other module reads
    settings from here instead of calling os.getenv() directly, so config
    stays centralized and testable (you can override `Settings` in tests
    with a different .env or constructor args).

Connects to:
    - Imported by db/mongo.py and db/elastic.py for connection strings
    - Imported by core/security.py for JWT secret/expiry
    - Imported by alerts/* for SMTP and webhook credentials
    - Imported by main.py for app metadata and CORS origins
"""
from functools import lru_cache
from typing import List

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- App metadata ---
    APP_NAME: str = "Cyber Threat Detection and Incident Response Dashboard"
    APP_ENV: str = Field(default="development")  # development | staging | production
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = Field(default=True)

    # --- CORS ---
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:5173", "http://localhost:3000"])

    # --- MongoDB (application data: users, incidents, rules, config) ---
    MONGO_URI: str = Field(default="mongodb://localhost:27017")
    MONGO_DB_NAME: str = Field(default="siem_dashboard")

    # --- Elasticsearch (log storage & search) ---
    ELASTIC_HOST: str = Field(default="http://localhost:9200")
    ELASTIC_USERNAME: str = Field(default="")
    ELASTIC_PASSWORD: str = Field(default="")
    ELASTIC_LOG_INDEX_PREFIX: str = Field(default="security-logs")
    ELASTIC_VERIFY_CERTS: bool = Field(default=False)

    # --- JWT Auth ---
    JWT_SECRET_KEY: str = Field(default="CHANGE_ME_IN_PRODUCTION_ENV_FILE")
    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)

    # --- Alerting: Email ---
    SMTP_HOST: str = Field(default="")
    SMTP_PORT: int = Field(default=587)
    SMTP_USERNAME: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    ALERT_EMAIL_FROM: str = Field(default="")
    ALERT_EMAIL_TO: List[str] = Field(default=[])

    # --- Alerting: Webhooks ---
    DISCORD_WEBHOOK_URL: str = Field(default="")
    TELEGRAM_BOT_TOKEN: str = Field(default="")
    TELEGRAM_CHAT_ID: str = Field(default="")

    # --- ML model artifacts ---
    ML_MODEL_DIR: str = Field(default="./ml/models")
    ML_MODEL_VERSION: str = Field(default="v1")

    # --- Rate limiting / ingestion ---
    MAX_UPLOAD_FILE_SIZE_MB: int = Field(default=25)

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        """Reject known-unsafe settings when the application is deployed."""
        if self.APP_ENV.lower() == "production":
            if self.DEBUG:
                raise ValueError("DEBUG must be false when APP_ENV is production")
            if self.JWT_SECRET_KEY.startswith("CHANGE_ME") or len(self.JWT_SECRET_KEY) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be a unique secret of at least 32 characters in production"
                )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings accessor. FastAPI dependencies should call
    `get_settings()` rather than instantiating Settings() directly,
    so the .env file is only parsed once per process.
    """
    return Settings()


settings = get_settings()
