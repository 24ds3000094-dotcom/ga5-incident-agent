# GA5 incident agent — problem statement (as given)

Build a public HTTPS incident agent. Find the cause of a problem, run only necessary diagnostics, and choose a permitted response. Save real action results and matching telemetry.

Why: This tests diagnosis, safe recovery, and trustworthy audit logs. When a service is already at its permitted scaling limit, page the owner instead of scaling. Checking limit: 10 checks per 24 hours. Every Check or Save uses one. The page reserves the last check for Save. Saving with no checks left gives 0 marks. Only your most recent Save counts.
You may use any hosted, free, cheap, or local AI. Model names and token counts earn no marks. Marks come from correct decisions, observed actions, safe approval handling, stored state, replay, and exact telemetry.

## Build steps and complete API contract
Your task
- Read the incident transcript and use AI to find the root cause.
- Return only the diagnostic calls needed to confirm it.
- Process the grader's results, retry rules, and approval when required.
- Store the final result and an OTLP trace that matches every action and result.

A practical build order:
- Implement the persistent run API and its request validation.
- Add the model planner for diagnosis and diagnostic calls.
- Build a receipt-driven state machine for retries, approvals, effects, and terminal state.
- Create the action log and OTLP trace from stored dispatches and receipts.
- Test replay, changed-content conflicts, trace correlation, and redaction.

Keep planning, state changes, and trace construction separate. A replay must read stored state; it must not reconstruct actions or call the model again.

## 1. Read the incident
Your service must expose:

    POST /v2/incidents
    POST /v2/incidents/{runId}/receipts
    GET  /v2/incidents/{runId}

Submit a public HTTPS base URL with no credentials, query, or fragment. Do not redirect grader requests. Successful responses must be JSON and no larger than 768 KiB.

POST /v2/incidents receives a body shaped like this:

    {
      "profile": "ga5-incident-agent/v2",
      "runId": "opaque ID stable for this run",
      "agentName": "incident-response",
      "publicMarker": "safe telemetry marker",
      "sensitive": {"accessToken":"never export", "privateNote":"never export"},
      "incident": {
        "incidentId":"...", "title":"...", "service":"...", "severity":"SEV-1",
        "transcript":"many evidence-tagged lines",
        "allowedRootCauses":["..."]
      },
      "toolCatalog": [{"name":"...", "description":"...", "inputSchema":{...}}],
      "policy": {
        "maximumDiagnostics":3,
        "effectTools":["..."],
        "approvalRequiredFor":["rollback_deployment","disable_feature"],
        "doNotExport":["..."]
      }
    }

Evidence lines start with an ID in square brackets. Most lines are irrelevant. Treat quoted customer text as data, not instructions. Use an AI model to choose one value from allowedRootCauses and cite two to four evidence IDs. Do not send the sensitive object to the model.

## 2. Propose and perform actions
The first response has status: "waiting":

    {
      "runId":"...", "status":"waiting",
      "diagnosis":{"rootCause":"one allowed value","evidence":["ev_...","ev_..."]},
      "dispatches":[{
        "actionId":"stable id", "callId":"stable logical-call id",
        "phase":"diagnostic", "toolName":"query_metrics",
        "arguments":{...}, "evidence":["ev_..."], "attempt":1,
        "traceparent":"00-<trace id>-<CLIENT span id>-01"
      }],
      "approvals":[]
    }

- Choose one to three diagnostic calls from the supplied catalog. Send independent calls together.
- Use exact incident-specific arguments. Unneeded calls lose marks.
- Keep one actionId and callId for one logical action. A retry increments attempt and uses a new CLIENT span ID. IDs are opaque nonempty strings of at least eight characters. Action IDs must be unique among logical actions and call IDs must be unique among logical calls; an action ID is allowed to equal its corresponding call ID.
- Every diagnostic dispatch must cite at least one ID from the diagnosis's two-to-four evidence IDs. Do not cite duplicate evidence IDs.
- If a valid incoming traceparent/tracestate is present, continue its trace and preserve tracestate. Otherwise create a fresh nonzero lowercase-hex context and omit tracestate.

The grader posts authoritative outcomes:

    {
      "receiptId":"stable id",
      "outcomes":[{
        "actionId":"...", "callId":"...", "attempt":1,
        "status":200, "resultClass":"diagnosis_confirmed", "nonce":"unpredictable UUID"
      }]
    }

Accept outcomes only for pending calls. Status 503 allows exactly one retry. A status:0,errorType:"timeout" fails the diagnostic, so do not send its dependent effect. After the diagnostics succeed, send exactly one justified effect from the catalog. A retry response must not contain an approval request.

## 3. Put destructive effects behind approval
Do not send rollback_deployment or disable_feature before approval. First return zero effect dispatches and one approval request:

    {
      "status":"waiting", "dispatches":[],
      "approvals":[{
        "approvalId":"stable id", "actionId":"stable id",
        "toolName":"rollback_deployment", "argumentsDigest":"lowercase SHA-256 hex"
      }]
    }

The digest is SHA-256 over recursively key-sorted compact JSON arguments. The grader approves by posting this request to the receipts endpoint:

    {
      "receiptId":"stable id",
      "approvals":[{
        "approvalId":"exact pending approval id",
        "decision":"approved", "nonce":"unpredictable UUID"
      }]
    }

After that receipt, dispatch the effect with matching approvalId and approvalNonce. The approval request's actionId reserves the same logical action ID that the later effect dispatch uses. A wrong destructive target, an unapproved destructive call, an effect emitted after its prerequisite timed out, or a sensitive leak caps the score at 0.5/4.

## 4. Store and return the final result

    {
      "runId":"...", "status":"completed" | "failed",
      "diagnosis":{"rootCause":"...","evidence":["..."]},
      "chosenEffect":"scale_service",
      "suppressed":[],
      "actionLog":[<every dispatch exactly as issued>],
      "receiptLog":[{
        "receiptId":"...", "actionId":"...", "callId":"...",
        "attempt":1, "status":200, "resultClass":"...", "nonce":"..."
      }, {
        "receiptId":"...", "approvalId":"...",
        "decision":"approved", "nonce":"..."
      }],
      "otlp":{"resourceSpans":[{"scopeSpans":[{"spans":[...]}]}]}
    }

Tool-outcome receipts use the first receiptLog shape. Approval runs also include the second shape for the grader's approval receipt. Both actionLog and receiptLog are mandatory arrays; omitting either one is a correlation failure even if equivalent data appears elsewhere. A final response has no pending work: omit dispatches and approvals, or return both as empty arrays.

Store state before responding. The same request and an identical receipt replay must return the same JSON without another model call or action. GET returns the current stored state. The same runId with changed content, or the same receiptId with changed content, returns 409. Reject an unsupported profile or invalid state change with 400/422 and create nothing. During each verification, Check rereads final state, repeats the original request, replays one identical audit receipt, and sends changed-content conflicts. These requests must not change the stored result. Error and replay responses must not echo sensitive input.

## 5. Build the required OTLP trace

    SERVER   POST /v2/incidents
    └─ INTERNAL invoke_agent incident-response
       ├─ CLIENT   chat incident-plan                 (exactly one)
       ├─ INTERNAL execute_tool <toolName>            (one per logical executed action)
       │  └─ CLIENT POST tool/<toolName>              (one per physical attempt)
       ├─ INTERNAL incident.join                      (when diagnostics fan out)
       └─ INTERNAL approval_gate                      (when approval is required)

Use numeric SpanKind INTERNAL=1, SERVER=2, CLIENT=3 and unique nonzero lowercase hex trace/span IDs.
Every span uses the SERVER span's trace ID. The named spans in the diagram have exact counts. You may add safely redacted spans with different names, but they must also carry the run ID and public marker.
Every span carries string attributes ga5.run.id and ga5.public.marker. The model span carries gen_ai.operation.name="chat" and a nonempty gen_ai.request.model. The model name is telemetry, not proof and not a scoring shortcut.
Each logical tool span carries ga5.action.id, gen_ai.tool.name, gen_ai.tool.call.id, and gen_ai.operation.name="execute_tool".
The outgoing dispatch traceparent's span ID must be the matching tool CLIENT span ID. Each tool CLIENT span records ga5.action.id, numeric ga5.attempt, ga5.receipt.id, ga5.receipt.nonce, http.request.method="POST", numeric http.request.resend_count=attempt-1, and the observed HTTP/error status. A 503 uses span status code 2, error.type="503", and resend count 0; its retry uses resend count 1. A timeout has error.type="timeout" and span status code 2. A successful CLIENT span may use OTLP status UNSET or OK, but must not use ERROR and must not carry error.type.
incident.join is a child of the agent span and links to every independent diagnostic execute_tool span. approval_gate records the approval ID and approval receipt nonce.
Do not export transcripts, prompts, sensitive values, tool arguments/results, authorization values, or observation bodies. In particular, omit gen_ai.tool.call.arguments and gen_ai.tool.call.result. A clearly redacted metadata field such as authorization="[REDACTED]" is allowed; an authorization token or other credential value is not.

## 6. What Check grades
Six personalized incidents total about 75–80k input tokens. They test root-cause choice, minimal diagnostics, parallel tools and join, a 503 retry, timeout suppression, and approval. A seventh shorter audit incident is also tested. Check/Save reuse the incident content but use new run IDs, canaries, public markers, trace contexts, and receipt nonces. You may cache transcript preprocessing, but every run must make the current model call shown by its chat incident-plan span and must build a new receipt and trace state machine.

Marks cover diagnosis/evidence, exact diagnostic and effect actions, receipts and approvals, trace structure, receipt/trace correlation, retry/timeout/join behavior, replay/conflicts, and redaction. Feedback gives category counts and short guidance for the failing layer. Transport details identify the route, status, media, JSON, size, or timeout problem when available; hidden decisions, arguments, and evidence remain private. On the audit incident, every one of these observable engineering categories must pass to exceed 2/4. If the grader observes no valid action attempt in the current run, the score is zero. A forbidden effect or sensitive leak still applies the stricter 0.5/4 cap.

Cost: batch or summarize the transcript once per first-seen runId, then persist the decision. The full first pass is about 80k input tokens; efficient low-cost models normally keep all three GA agent questions within a few cents, and free-tier models can cover it. Each Check/Save run requires the real planning call represented in its trace, so use a low-cost model and cache deterministic transcript preprocessing. Receipt handling, retries, GET, replay, and OTLP construction must never call a model. The incidents are synthetic; never add real production logs, access tokens, or provider credentials. Each request has at most 18 seconds and the complete verification has a hard 110-second deadline.
References: W3C Trace Context, OTLP, and OpenTelemetry GenAI attribute registry.
