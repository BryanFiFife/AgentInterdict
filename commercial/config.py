from dataclasses import dataclass
import os
from pathlib import Path

@dataclass
class Settings:
    db_path: Path = Path(os.getenv('MG_COMMERCE_DB', 'commercial.db'))
    public_url: str = os.getenv('MG_PUBLIC_URL', 'http://127.0.0.1:43848').rstrip('/')
    stripe_secret_key: str = os.getenv('STRIPE_SECRET_KEY', '')
    stripe_webhook_secret: str = os.getenv('STRIPE_WEBHOOK_SECRET', '')
    stripe_portal_configuration: str = os.getenv('STRIPE_PORTAL_CONFIGURATION', '')
    resend_api_key: str = os.getenv('RESEND_API_KEY', '')
    resend_webhook_secret: str = os.getenv('RESEND_WEBHOOK_SECRET', '')
    email_from: str = os.getenv('MG_EMAIL_FROM', 'MemoryGuard <noreply@example.invalid>')
    operator_key: str = os.getenv('MG_COMMERCE_OPERATOR_KEY', '')
    cron_secret: str = os.getenv('MG_COMMERCE_CRON_SECRET', '')
    signing_private_key: Path = Path(os.getenv('MG_LICENSE_PRIVATE_KEY', 'license_private_key.pem'))
    signing_public_key: Path = Path(os.getenv('MG_LICENSE_PUBLIC_KEY', 'memoryguard/license_public_key.pem'))
    max_installations: int = int(os.getenv('MG_MAX_INSTALLATIONS', '3'))

settings = Settings()
