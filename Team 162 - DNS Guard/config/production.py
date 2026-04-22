import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dnsguard_default_key")
    DEBUG = False
    TESTING = False
    DATABASE_URL = (
        f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    )
    ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", "3.5"))
    SLIDING_WINDOW_SECONDS = int(os.getenv("SLIDING_WINDOW_SECONDS", "60"))
    QUERY_FREQUENCY_THRESHOLD = int(os.getenv("QUERY_FREQUENCY_THRESHOLD", "50"))
    TYPOSQUATTING_EDIT_DISTANCE = int(os.getenv("TYPOSQUATTING_EDIT_DISTANCE", "2"))
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    LOG_PATH = "data/logs/dnsguard.log"
    GRAPH_DATA_PATH = "data/graph_data.json"

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    DEBUG = True

config_map = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "testing":     TestingConfig
}

def get_config():
    env = os.getenv("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)