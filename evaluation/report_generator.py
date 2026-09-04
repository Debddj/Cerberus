import json


def generate_report():
    with open("evaluation_results.json") as f:
        data = json.load(f)
    print("Generated Summary Report from Benchmark Run:")
    print(f"Standard TPR: {data['metrics']['standard_tpr'] * 100:.1f}%")
    print(f"Evasion Resistance TPR: {data['metrics']['evasion_tpr'] * 100:.1f}%")
    print(f"False Positive Rate: {data['metrics']['false_positive_rate'] * 100:.1f}%")
    print(f"P95 Latency Overhead: {data['metrics']['latency_p95_ms']} ms")


if __name__ == "__main__":
    generate_report()
