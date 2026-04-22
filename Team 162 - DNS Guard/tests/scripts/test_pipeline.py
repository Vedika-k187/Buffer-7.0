import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.pipeline import run_full_pipeline

print("Running full unified pipeline with simulator...")
results = run_full_pipeline(use_simulator=True)

print("\nPipeline Results Summary:")
print(f"  Duration        : {results['summary']['duration_seconds']}s")
print(f"  Total Records   : {results['summary']['total_records']}")
print(f"  Total Threats   : {results['summary']['total_threats']}")
print(f"  Critical        : {results['summary']['critical_count']}")
print(f"  High            : {results['summary']['high_count']}")
print(f"  Medium          : {results['summary']['medium_count']}")