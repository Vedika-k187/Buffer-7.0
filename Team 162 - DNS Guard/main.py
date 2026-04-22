import sys
import os
from dotenv import load_dotenv
load_dotenv()

from config.logger import get_logger
log = get_logger()


# ── HELP ──────────────────────────────────────────────────────────────────────

def print_help():
    print("""
DNSGuard — Intelligent DNS Threat Intelligence Platform
========================================================

Usage:
  python main.py [command] [options]

Commands:
  dashboard              Start the web dashboard (http://localhost:5000)
  pipeline               Run full analysis on existing database records
  simulate               Inject attack simulation data then run full pipeline
  live                   Capture real DNS traffic (unlimited, Ctrl+C to stop)
  live <iface>           Capture on a specific network interface
  live <iface> <count>   Capture exactly N packets then stop
  pcap <file>            Analyze a PCAP file through the full pipeline
  report                 Generate JSON + PDF threat report
  test                   Run all unit and integration tests
  interfaces             List available network interfaces
  help                   Show this help message

Examples:
  python main.py dashboard
  python main.py simulate
  python main.py pipeline
  python main.py live
  python main.py live Wi-Fi
  python main.py live Wi-Fi 1000
  python main.py pcap data/pcap_samples/capture.pcap
  python main.py report
  python main.py interfaces
    """)


# ── COMMANDS ──────────────────────────────────────────────────────────────────

def cmd_dashboard():
    log.info("Starting DNSGuard Dashboard on http://127.0.0.1:5000 ...")
    from dashboard.app import app, socketio
    socketio.run(
        app,
        debug=False,           # set True only while developing
        port=5000,
        host="0.0.0.0",
        allow_unsafe_werkzeug=True,
    )


def cmd_pipeline():
    from intelligence.pipeline import run_full_pipeline
    log.info("Running pipeline on existing database records...")
    results = run_full_pipeline(use_simulator=False)
    summary = results.get("summary", {})
    log.info(f"Pipeline complete.")
    log.info(f"  Total threats : {summary.get('total_threats', '?')}")
    log.info(f"  Critical      : {summary.get('critical_count', '?')}")
    log.info(f"  High          : {summary.get('high_count', '?')}")
    log.info(f"  Duration      : {summary.get('duration_seconds', '?')}s")


def cmd_simulate():
    from intelligence.pipeline import run_full_pipeline
    log.info("Running attack simulation + full pipeline...")
    results = run_full_pipeline(use_simulator=True)
    summary = results.get("summary", {})
    log.info(f"Simulation + pipeline complete.")
    log.info(f"  Total threats : {summary.get('total_threats', '?')}")
    log.info(f"  Critical      : {summary.get('critical_count', '?')}")
    log.info(f"  High          : {summary.get('high_count', '?')}")
    log.info(f"  Duration      : {summary.get('duration_seconds', '?')}s")


def cmd_live(interface=None, count=None):
    """
    Real-time DNS capture mode.
    - Captures live UDP/53 traffic via Scapy + Npcap
    - Deduplicates repeated queries (3s window)
    - Optionally scores each domain in real time
    - Saves to PostgreSQL
    - Does NOT run the heavy pipeline automatically (run 'pipeline' after)
    """
    from capture.live_capture import start_live_capture
    from capture.queue_processor import process_queue

    log.info("=" * 55)
    log.info("DNSGuard LIVE CAPTURE MODE")
    log.info("=" * 55)

    if interface is None:
        log.info("No interface specified — Scapy will auto-select.")
        log.info("Tip: run  python main.py interfaces  to list options.")

    if count is None:
        log.info("Packet count: unlimited. Press Ctrl+C to stop.")
    else:
        log.info(f"Packet count: {count}")

    try:
        start_live_capture(interface=interface, packet_count=count)
        process_queue()   # flush any remaining items in the queue after capture ends
    except KeyboardInterrupt:
        log.info("Live capture stopped.")
        try:
            process_queue()
        except Exception:
            pass
    except PermissionError:
        log.error("Permission denied.")
        log.error("On Windows: run this terminal as Administrator.")
        log.error("On Linux  : run with sudo, or grant cap_net_raw capability.")
        sys.exit(1)
    except OSError as e:
        log.error(f"Interface error: {e}")
        log.error("Run  python main.py interfaces  to see valid interface names.")
        sys.exit(1)

    log.info("Live capture ended.")
    log.info("Run  python main.py pipeline  to analyse captured traffic.")


def cmd_pcap(filepath):
    if not os.path.exists(filepath):
        log.error(f"PCAP file not found: {filepath}")
        sys.exit(1)

    from intelligence.pipeline import run_full_pipeline
    log.info(f"Analyzing PCAP file: {filepath}")
    results = run_full_pipeline(pcap_path=filepath)
    summary = results.get("summary", {})
    log.info(f"PCAP analysis complete.")
    log.info(f"  Total threats : {summary.get('total_threats', '?')}")
    log.info(f"  Critical      : {summary.get('critical_count', '?')}")
    log.info(f"  High          : {summary.get('high_count', '?')}")


def cmd_report():
    from intelligence.report_generator import export_json_report, generate_pdf_report
    log.info("Generating reports...")
    results = {"summary": {}, "steps": {}}
    json_path = export_json_report(results)
    pdf_path  = generate_pdf_report(results)
    log.info(f"JSON report : {json_path}")
    log.info(f"PDF report  : {pdf_path}")
    log.info("Open PDF with:  start data\\logs\\dnsguard_report.pdf")


def cmd_interfaces():
    """List all network interfaces Scapy can see on this machine."""
    try:
        from scapy.all import get_if_list, conf
        interfaces = get_if_list()
        print()
        print("Available network interfaces:")
        print("-" * 40)
        for iface in interfaces:
            marker = " ← (Scapy default)" if iface == conf.iface else ""
            print(f"  {iface}{marker}")
        print()
        print("Usage:  python main.py live <interface_name>")
        print("Example: python main.py live Wi-Fi")
        print()
    except Exception as e:
        log.error(f"Could not list interfaces: {e}")
        log.error("Make sure Npcap is installed: https://npcap.com")


def cmd_test():
    log.info("Running all unit and integration tests...")
    exit_code = os.system("python -m pytest tests/ -v --tb=short")
    if exit_code == 0:
        log.info("All tests passed.")
    else:
        log.error("Some tests failed. Check output above.")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] == "help":
        print_help()

    elif args[0] == "dashboard":
        cmd_dashboard()

    elif args[0] == "pipeline":
        cmd_pipeline()

    elif args[0] == "simulate":
        cmd_simulate()

    elif args[0] == "live":
        interface = args[1] if len(args) > 1 else None
        count     = int(args[2]) if len(args) > 2 else None
        cmd_live(interface=interface, count=count)

    elif args[0] == "pcap":
        if len(args) < 2:
            log.error("Please provide a PCAP file path.")
            print("Usage: python main.py pcap data/pcap_samples/file.pcap")
        else:
            cmd_pcap(args[1])

    elif args[0] == "report":
        cmd_report()

    elif args[0] == "test":
        cmd_test()

    elif args[0] == "interfaces":
        cmd_interfaces()

    else:
        log.error(f"Unknown command: '{args[0]}'")
        print_help()
        sys.exit(1)