import os
from dotenv import load_dotenv
load_dotenv()

from waitress import serve
from dashboard.app import app
from config.logger import get_logger

log = get_logger()

if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.getenv("PORT", 5000))

    log.info("=" * 55)
    log.info("DNSGUARD SERVER STARTING")
    log.info(f"Host     : {host}")
    log.info(f"Port     : {port}")
    log.info(f"Env      : {os.getenv('FLASK_ENV', 'development')}")
    log.info(f"Dashboard: http://127.0.0.1:{port}")
    log.info("=" * 55)

    serve(app, host=host, port=port, threads=4)