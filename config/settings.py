from pydantic_settings import BaseSettings
from typing import ClassVar


class Settings(BaseSettings):
    # MongoDB Configuration
    MONGODB_URL: str
    MONGODB_DB_NAME: str
    MONGODB_READ_COLLECTION: str
    MONGODB_WRITE_COLLECTION: str
    
    # Supabase Configuration
    SUPABASE_URL: str
    SUPABASE_KEY: str
    SUPABASE_BUCKET: str
    
    # VirusTotal Configuration
    VIRUSTOTAL_API_KEY: str
    
    model_config: ClassVar = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "ignore"
    }


settings = Settings()  # type: ignore[call-arg]
