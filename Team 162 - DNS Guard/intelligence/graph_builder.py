import networkx as nx
import json
from config.database import get_connection
from datetime import timedelta

def build_graph():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, src_ip, timestamp
        FROM dns_records
        ORDER BY timestamp ASC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    G = nx.DiGraph()

    # Add all domains as nodes
    for domain, src_ip, timestamp in rows:
        G.add_node(domain, src_ip=src_ip, timestamp=str(timestamp))

    # Edge Rule 1 — Subdomain to parent relationship
    for domain, _, _ in rows:
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            if parent != domain:
                G.add_edge(domain, parent, relationship="subdomain_of")
                save_relationship(domain, parent, "subdomain_of", None)

    # Edge Rule 2 — Same IP queried multiple domains
    ip_to_domains = {}
    for domain, src_ip, _ in rows:
        if src_ip not in ip_to_domains:
            ip_to_domains[src_ip] = []
        if domain not in ip_to_domains[src_ip]:
            ip_to_domains[src_ip].append(domain)

    for ip, domains in ip_to_domains.items():
        if len(domains) > 1:
            for i in range(len(domains)):
                for j in range(i + 1, len(domains)):
                    G.add_edge(
                        domains[i],
                        domains[j],
                        relationship="same_ip",
                        shared_ip=ip
                    )
                    save_relationship(domains[i], domains[j], "same_ip", ip)

    # Edge Rule 3 — Queries within 60 seconds window
    rows_list = list(rows)
    for i in range(len(rows_list)):
        for j in range(i + 1, len(rows_list)):
            d1, ip1, t1 = rows_list[i]
            d2, ip2, t2 = rows_list[j]

            if abs((t2 - t1).total_seconds()) <= 60 and ip1 == ip2 and d1 != d2:
                G.add_edge(d1, d2, relationship="time_correlated")
                save_relationship(d1, d2, "time_correlated", ip1)

            if abs((t2 - t1).total_seconds()) > 60:
                break

    return G

def save_relationship(source, target, rel_type, shared_ip):
    conn = get_connection()
    cursor = conn.cursor()

    # Avoid duplicate relationships
    cursor.execute("""
        SELECT id FROM domain_relationships
        WHERE source_domain = %s AND target_domain = %s AND relationship_type = %s
    """, (source, target, rel_type))

    if cursor.fetchone():
        cursor.close()
        conn.close()
        return

    cursor.execute("""
        INSERT INTO domain_relationships
        (source_domain, target_domain, relationship_type, shared_ip)
        VALUES (%s, %s, %s, %s)
    """, (source, target, rel_type, shared_ip))

    conn.commit()
    cursor.close()
    conn.close()

def get_graph_stats(G):
    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "connected_components": nx.number_weakly_connected_components(G),
        "most_connected": sorted(G.degree(), key=lambda x: x[1], reverse=True)[:5]
    }

def export_graph_json(G):
    nodes = []
    for node, data in G.nodes(data=True):
        nodes.append({
            "id": node,
            "label": node,
            "src_ip": data.get("src_ip", "unknown")
        })

    edges = []
    for source, target, data in G.edges(data=True):
        edges.append({
            "from": source,
            "to": target,
            "label": data.get("relationship", "related"),
            "shared_ip": data.get("shared_ip", "")
        })

    graph_data = {"nodes": nodes, "edges": edges}

    with open("data/graph_data.json", "w") as f:
        json.dump(graph_data, f, indent=2)

    print(f"Graph exported to data/graph_data.json")
    return graph_data

def fetch_relationships_from_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source_domain, target_domain, relationship_type, shared_ip
        FROM domain_relationships
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows