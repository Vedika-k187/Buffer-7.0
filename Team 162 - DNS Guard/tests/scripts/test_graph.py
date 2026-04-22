import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.graph_builder import (
    build_graph,
    get_graph_stats,
    export_graph_json,
    fetch_relationships_from_db
)

print("=" * 55)
print("DOMAIN RELATIONSHIP GRAPH TEST")
print("=" * 55)

print("\nBuilding domain relationship graph...")
G = build_graph()

print("\nGraph Statistics:")
stats = get_graph_stats(G)
print(f"  Total Nodes (domains)   : {stats['total_nodes']}")
print(f"  Total Edges (relations) : {stats['total_edges']}")
print(f"  Connected Components    : {stats['connected_components']}")

print("\nTop 5 most connected domains:")
for domain, degree in stats["most_connected"]:
    print(f"  {domain:<40} Connections: {degree}")

print("\nExporting graph to JSON...")
graph_data = export_graph_json(G)
print(f"  Nodes exported: {len(graph_data['nodes'])}")
print(f"  Edges exported: {len(graph_data['edges'])}")

print("\nFetching relationships from database...")
relationships = fetch_relationships_from_db()
print(f"  Total relationships saved: {len(relationships)}")

print("\nSample relationships:")
for row in relationships[:5]:
    print(f"  {row[0]:<30} --[{row[2]}]--> {row[1]}")