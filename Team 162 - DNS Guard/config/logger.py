from loguru import logger
import os

os.makedirs("data/logs", exist_ok=True)

# Remove default handler
logger.remove()

# Console output
logger.add(
    sink=lambda msg: print(msg, end=""),
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
    level="INFO",
    colorize=True
)

# File output - all logs
logger.add(
    "data/logs/dnsguard.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {module} | {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="7 days",
    compression="zip"
)

# Separate file for threats only
logger.add(
    "data/logs/threats.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}",
    level="WARNING",
    rotation="5 MB",
    retention="30 days"
)

def get_logger():
    return logger