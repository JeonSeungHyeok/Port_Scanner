import json

def save_result_as_json(results, scanMethod, outputFile=None):
    if scanMethod == "version":
        resultsJson = [
            {"port": port, "state": state, "service": service, "banner": banner}
            for port, state, service, banner in results
        ]
    else:
        resultsJson = [
            {"port": port, "state": state} for port, state in results
        ]

    data = {
        "scanMethod": scanMethod,
        "results": resultsJson
    }

    outputFile = outputFile or "scanResults.json" 

    with open(outputFile, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[INFO] Results saved as JSON to {outputFile}")