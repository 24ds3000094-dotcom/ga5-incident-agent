"""Save the last grader incidents (catalog, transcript, model output) to debug_details.json."""
import json, urllib.request
BASE = "https://ga5-incident-agent.24ds3000094.workers.dev"
req = urllib.request.Request(f"{BASE}/v2/debug/details?limit=12", headers={"User-Agent": "ga5-debug/1.0"})
data = json.load(urllib.request.urlopen(req))
json.dump(data, open("debug_details.json", "w"), indent=1)
for d in data["details"]:
    print(d["t"][11:19], d["incident"]["incidentId"], "tools:", [t["name"] for t in d["toolCatalog"]],
          "transcript chars:", len(d.get("transcript", "")))
print("\nSaved debug_details.json - upload this file in the chat.")
