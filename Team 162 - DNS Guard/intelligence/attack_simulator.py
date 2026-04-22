import random
import base64
import string
from datetime import datetime, timedelta
from config.database import get_connection
from capture.dns_record import DNSRecord
from capture.db_writer import save_dns_record

def random_string(length):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def simulate_dns_tunneling(base_domain="attacker.com", count=80):
    print(f"\nSimulating DNS Tunneling → {base_domain}")
    records = []
    base_time = datetime.now()

    for i in range(count):
        subdomain = random_string(12)
        domain = f"{subdomain}.{base_domain}"
        timestamp = base_time + timedelta(seconds=i * 0.5)
        src_ip = f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"

        record = DNSRecord(
            domain=domain,
            src_ip=src_ip,
            timestamp=timestamp,
            query_type="TXT"
        )
        save_dns_record(record)
        save_simulated_attack("DNS_TUNNELING", domain, src_ip)
        records.append(record)

    print(f"  Generated {count} tunneling queries to {base_domain}")
    return records

def simulate_dga_domains(count=20):
    print(f"\nSimulating DGA Domain Attack")
    tlds = [".com", ".net", ".org", ".info"]
    records = []
    base_time = datetime.now()

    for i in range(count):
        length = random.randint(12, 20)
        domain = random_string(length) + random.choice(tlds)
        timestamp = base_time + timedelta(seconds=i * 2)
        src_ip = f"192.168.{random.randint(1,5)}.{random.randint(1,254)}"

        record = DNSRecord(
            domain=domain,
            src_ip=src_ip,
            timestamp=timestamp,
            query_type="A"
        )
        save_dns_record(record)
        save_simulated_attack("DGA_DOMAIN", domain, src_ip)
        records.append(record)

    print(f"  Generated {count} DGA domains")
    return records

def simulate_typosquatting():
    print(f"\nSimulating Typosquatting Attack")
    typo_domains = [
        "g00gle.com", "gooogle.com", "googIe.com",
        "faceb00k.com", "facebok.com",
        "amaz0n.com", "amazoon.com",
        "paypa1.com", "paypall.com",
        "micros0ft.com", "micosoft.com"
    ]

    records = []
    base_time = datetime.now()

    for i, domain in enumerate(typo_domains):
        timestamp = base_time + timedelta(seconds=i * 3)
        src_ip = f"172.16.{random.randint(0,5)}.{random.randint(1,254)}"

        record = DNSRecord(
            domain=domain,
            src_ip=src_ip,
            timestamp=timestamp,
            query_type="A"
        )
        save_dns_record(record)
        save_simulated_attack("TYPOSQUATTING", domain, src_ip)
        records.append(record)

    print(f"  Generated {len(typo_domains)} typosquatting domains")
    return records

def simulate_steganography(base_domain="evil-c2.net", messages=None):
    print(f"\nSimulating DNS Steganography Attack")

    if messages is None:
        messages = ["secret_payload", "exfil_data", "user_credentials", "hello_world"]

    records = []
    base_time = datetime.now()

    for i, message in enumerate(messages):
        encoded = base64.b64encode(message.encode()).decode().rstrip("=")
        domain = f"{encoded}.{base_domain}"
        timestamp = base_time + timedelta(seconds=i * 5)
        src_ip = f"10.10.{random.randint(0,5)}.{random.randint(1,254)}"

        record = DNSRecord(
            domain=domain,
            src_ip=src_ip,
            timestamp=timestamp,
            query_type="TXT"
        )
        save_dns_record(record)
        save_simulated_attack("STEGANOGRAPHY", domain, src_ip)
        records.append(record)

    print(f"  Generated {len(messages)} steganography queries to {base_domain}")
    return records

def save_simulated_attack(attack_type, domain, src_ip):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO simulated_attacks (attack_type, domain, src_ip)
        VALUES (%s, %s, %s)
    """, (attack_type, domain, src_ip))

    conn.commit()
    cursor.close()
    conn.close()

def run_full_simulation():
    print("=" * 55)
    print("RUNNING FULL ATTACK SIMULATION")
    print("=" * 55)

    r1 = simulate_dns_tunneling()
    r2 = simulate_dga_domains()
    r3 = simulate_typosquatting()
    r4 = simulate_steganography()

    total = len(r1) + len(r2) + len(r3) + len(r4)
    print(f"\nTotal simulated records injected: {total}")
    return total

def fetch_simulation_summary():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, COUNT(*)
        FROM simulated_attacks
        GROUP BY attack_type
        ORDER BY COUNT(*) DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows