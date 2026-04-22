import os
from dotenv import load_dotenv

load_dotenv()


# Database
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Detection Thresholds
ENTROPY_THRESHOLD = 3.3
SLIDING_WINDOW_SECONDS = 60
QUERY_FREQUENCY_THRESHOLD = 50
TYPOSQUATTING_EDIT_DISTANCE = 2

# Paths
LOG_PATH = "data/logs/threats.log"