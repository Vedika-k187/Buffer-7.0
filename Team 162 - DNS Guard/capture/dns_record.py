from dataclasses import dataclass
from datetime import datetime

@dataclass
class DNSRecord:
    domain: str
    src_ip: str
    timestamp: datetime
    query_type: str
    entropy_score: float = 0.0
    threat_score: int = 0
    is_suspicious: bool = False
    detection_reasons: str = ""