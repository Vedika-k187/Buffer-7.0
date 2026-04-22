from scapy.all import sniff, DNS, DNSQR, IP
from datetime import datetime
import time
import threading

from capture.dns_record import DNSRecord
from capture.packet_queue import add_to_queue
from capture.db_writer import save_dns_record

# ── OPTIONAL IMPORTS (graceful fallback) ─────────────────────────────────────

try:
    from config.logger import get_logger
    log = get_logger()
except Exception:
    import logging
    log = logging.getLogger("live_capture")

try:
    from intelligence.threat_scorer import score_domain
    SCORING_ENABLED = True
except Exception:
    SCORING_ENABLED = False

# ── STATS COUNTER ─────────────────────────────────────────────────────────────

_stats = {
    "captured":  0,
    "processed": 0,
    "threats":   0,
    "errors":    0,
}

# ── DEDUP WINDOW ──────────────────────────────────────────────────────────────
# Same domain within DEDUP_WINDOW seconds → skip heavy processing
# (still emitted to dashboard + counted)

DEDUP_WINDOW      = 3        # seconds
_domain_last_seen = {}
_dedup_lock       = threading.Lock()


def _should_process(domain: str) -> bool:
    """Return True if domain hasn't been deeply processed in the last DEDUP_WINDOW seconds."""
    now = time.time()
    with _dedup_lock:
        last = _domain_last_seen.get(domain, 0)
        if now - last > DEDUP_WINDOW:
            _domain_last_seen[domain] = now
            return True
    return False


# ── SEVERITY COLOUR MAP (console) ─────────────────────────────────────────────

_SEV_PREFIX = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH    ]",
    "MEDIUM":   "[MEDIUM  ]",
    "LOW":      "[LOW     ]",
}


# ── PACKET HANDLER ────────────────────────────────────────────────────────────

def process_packet(packet):
    """Called by Scapy for every captured packet."""
    global _stats

    # Only handle DNS query packets
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return

    try:
        # ── Extract fields ────────────────────────────────────────────────────
        raw_name = packet[DNSQR].qname
        domain   = (raw_name.decode(errors="ignore") if isinstance(raw_name, bytes) else raw_name).rstrip(".")

        if not domain or len(domain) < 3:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

        query_type = {
            1:  "A",
            28: "AAAA",
            15: "MX",
            16: "TXT",
            5:  "CNAME",
            12: "PTR",
            33: "SRV",
        }.get(packet[DNSQR].qtype, "OTHER")

        timestamp = datetime.now()
        _stats["captured"] += 1

        # ── Lightweight console + DB write (always) ───────────────────────────
        record = DNSRecord(
            domain=domain,
            src_ip=src_ip,
            timestamp=timestamp,
            query_type=query_type,
        )
        add_to_queue(record)

        # ── Heavy processing only when dedup window has passed ────────────────
        if not _should_process(domain):
            return

        _stats["processed"] += 1

        # ── Save to DB ────────────────────────────────────────────────────────
        try:
            save_dns_record(record)
        except Exception as db_err:
            log.warning(f"DB write failed for {domain}: {db_err}")
            _stats["errors"] += 1

        # ── Optional threat scoring ───────────────────────────────────────────
        score    = None
        severity = "INFO"

        if SCORING_ENABLED:
            try:
                result   = score_domain(domain, timestamp)   # returns dict
                score    = result.get("final_score", 0)
                severity = result.get("severity", "LOW")
                if result.get("is_threat"):
                    _stats["threats"] += 1
            except Exception as score_err:
                log.debug(f"Scoring skipped for {domain}: {score_err}")

        # ── Console output ────────────────────────────────────────────────────
        prefix = _SEV_PREFIX.get(severity, "[INFO    ]")
        ts     = timestamp.strftime("%H:%M:%S")

        if score is not None and score > 0:
            print(f"{ts} {prefix} {domain:<45} {src_ip:<16} {query_type:<6} score={score}")
        else:
            print(f"{ts} [INFO    ] {domain:<45} {src_ip:<16} {query_type}")

    except Exception as e:
        _stats["errors"] += 1
        log.error(f"Packet processing error: {e}")


# ── STATS PRINTER ─────────────────────────────────────────────────────────────

def _print_stats_banner(interface: str, count):
    iface_str = interface or "default (auto)"
    count_str = str(count) if count else "unlimited (Ctrl+C to stop)"
    print()
    print("=" * 60)
    print("  DNSGuard — Live DNS Capture")
    print("=" * 60)
    print(f"  Interface : {iface_str}")
    print(f"  Packets   : {count_str}")
    print(f"  Filter    : UDP port 53 (DNS queries only)")
    print(f"  Scoring   : {'enabled' if SCORING_ENABLED else 'disabled (model not loaded)'}")
    print(f"  Dedup     : {DEDUP_WINDOW}s window")
    print("=" * 60)
    print("  TIME     SEVERITY   DOMAIN                                        IP               TYPE")
    print("-" * 60)


def _print_stats_summary():
    print()
    print("=" * 60)
    print("  Live Capture Summary")
    print("-" * 60)
    print(f"  Packets captured   : {_stats['captured']}")
    print(f"  Domains processed  : {_stats['processed']}")
    print(f"  Threats detected   : {_stats['threats']}")
    print(f"  Errors             : {_stats['errors']}")
    print("=" * 60)


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def start_live_capture(interface=None, packet_count=None):
    """
    Start capturing live DNS traffic.

    Args:
        interface   : Network interface name (None = Scapy auto-selects)
        packet_count: Number of packets to capture (None = infinite until Ctrl+C)
    """
    _print_stats_banner(interface, packet_count)

    try:
        sniff(
            filter="udp port 53 and not port 5353",   # exclude mDNS
            prn=process_packet,
            iface=interface,
            store=False,                               # do not keep packets in RAM
            count=packet_count or 0,                  # 0 = infinite in Scapy
        )
    except PermissionError:
        log.error("Permission denied. Run as Administrator (Windows) or with sudo (Linux).")
        raise
    except OSError as e:
        log.error(f"Interface error: {e}")
        log.error("Run:  python -c \"from scapy.all import get_if_list; print(get_if_list())\"")
        log.error("Then: python main.py live <interface_name>")
        raise
    except KeyboardInterrupt:
        log.info("Capture stopped by user.")
    finally:
        _print_stats_summary()