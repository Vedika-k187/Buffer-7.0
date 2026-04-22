import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.attack_simulator import run_full_simulation, fetch_simulation_summary

print("=" * 55)
print("ATTACK REPLAY SIMULATOR TEST")
print("=" * 55)

total = run_full_simulation()

print("\nSimulation Summary from Database:")
summary = fetch_simulation_summary()
for attack_type, count in summary:
    print(f"  {attack_type:<20} : {count} records")

print(f"\nTotal injected: {total}")