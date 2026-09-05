from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class CerberusSettings(BaseSettings):
    """Central configuration for Cerberus runtime firewall."""

    app_name: str = "Cerberus"
    mode: Literal["enforce", "audit"] = "enforce"
    debug: bool = False

    # Network and Proxy settings
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8000
    metrics_port: int = 9090

    # Multi-tenant Auth & Rate Limiting
    require_signed_identity: bool = False
    hmac_secret_key: str = ""
    rate_limit_per_minute: int = 120

    # OPA Policy Engine
    opa_url: str = "http://localhost:8181/v1/data"
    opa_timeout_seconds: float = 2.0
    fail_closed: bool = True

    # Behavioral Engine Thresholds
    warm_threshold_calls: int = 100
    risk_quarantine_threshold: float = 0.90
    risk_block_threshold: float = 0.70
    risk_flag_threshold: float = 0.40

    # Online learning & retraining intervals
    if_refit_interval: int = 200
    online_learning_interval_seconds: float = 60.0

    # Distributed State
    redis_url: str = ""

    # Logging and Persistence
    log_path: str = "cerberus_audit.jsonl"
    pins_db_path: str = "cerberus_pins.db"
    baselines_dir: str = "baselines"
    encrypt_logs: bool = True
    log_encryption_key: str = ""

    # Static scanner toggles
    trifecta_override: bool = False

    # Scope enforcement: "learn" (monitor + log, fail-open) or "strict" (fail-closed from call #1)
    scope_enforcement_mode: Literal["learn", "strict"] = "learn"

    model_config = SettingsConfigDict(env_prefix="CERBERUS_", env_file=".env", extra="ignore")


settings = CerberusSettings()
