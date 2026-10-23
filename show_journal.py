"""Print the agent's debug journal compactly.  Usage: python3 show_journal.py [limit]"""
import json, sys, urllib.request
BASE = "https://ga5-incident-agent.24ds3000094.workers.dev"
limit = sys.argv[1] if len(sys.argv) > 1 else "120"
req = urllib.request.Request(f"{BASE}/v2/debug/recent?limit={limit}", headers={"User-Agent": "ga5-debug/1.0"})
events = json.load(urllib.request.urlopen(req))["events"][::-1]  # oldest first
for e in events:
    k, rid = e.get("kind"), str(e.get("runId"))[-10:]
    t = e.get("t", "")[11:19]
    if k == "create":
        print(f"\n{t} CREATE {rid} {e.get('incidentId')} svc={e.get('service')} {e.get('ms')}ms "
              f"model={e.get('model')} err={e.get('modelErr')} tries={e.get('modelAttempts')} {e.get('modelDetail') or ''}")
        print(f"   allowed={e.get('allowedRootCauses')}  evidenceIdsFound={e.get('evidenceIdsFound')}")
        print(f"   diagnosis={e.get('diagnosis')}")
        for d in e.get("dispatches", []):
            print(f"   diag  {d['tool']} {json.dumps(d['args'])} ev={d['evidence']}")
        pe = e.get("plannedEffect") or {}
        print(f"   effect {pe.get('toolName')} {json.dumps(pe.get('arguments'))}  approvalFor={e.get('approvalRequiredFor')}")
    elif k == "receipt":
        print(f"{t} RECEIPT {rid} in={e.get('outcomes')} appr={e.get('approvals')} -> "
              f"{e.get('runStatus')} new={e.get('newDispatches')} ask={e.get('approvalRequested')} "
              f"chosen={e.get('chosenEffect')} suppressed={len(e.get('suppressed') or [])}")
    elif k in ("receipt-reject", "create-reject"):
        print(f"{t} !! {k.upper()} {rid} {e.get('code')} {e.get('reason')}")
        for key in ("keys", "sentOutcomes", "sentApprovals", "pending", "pendingApproval", "runStatus"):
            if e.get(key) not in (None, [], ""):
                print(f"      {key}: {json.dumps(e.get(key))}")
    elif k == "error":
        print(f"{t} !! ERROR {e.get('message')}")
    else:
        print(f"{t} {k} {rid} {e.get('receiptId', '')} {e.get('status', '')}")
