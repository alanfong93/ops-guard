# 0014 — Approved-field hosted Jev advisory

- Status: Accepted design; implementation pending
- Date: 2026-10-04
- Runtime: OpenCode/openai-gpt-6.1-sol
- Decided by: plan-loop; Alan selected approved fields and explicitly waived the three-seat tribunal minimum for this run
- Review: Sol and GLM all-plan correction reviews both 8.8/10; Grok unavailable. One Sol tribunal response is advisory, not a completed tribunal.

## Context

ADR 0009 defines the existing local, audit-only judge. Its Qwen evaluations fail usefulness gates. A native `jev-1.13.0` full-state experiment passed the same semantic and full-map gates, but its six deterministic fixtures exercised local controls, not a production Jev adapter. The experiment is candidate-selection evidence, not permission to disclose operational data or eligibility for #65.

Alan chose an explicit approved-fields outbound policy, with unsupported input rejected before transmission. This changes the measured input: the actual serving projection must be evaluated anew. The existing caller-advisory decision and accepted host-relay risk remain settled; this ADR does not expose that response.

## Decision

### Operator configuration

Keep `local` as the default `OPS_GUARD_JUDGE_BACKEND`; opt-in `jev` selects one internal native Jev adapter. No automatic fallback or host override exists. Local mode requires no hosted settings. Hosted mode requires:

- `OPS_GUARD_JEV_ENDPOINT`
- `OPS_GUARD_JEV_ALLOWED_ENDPOINTS`, comma-separated exact endpoint identities
- `OPS_GUARD_JEV_BEARER_TOKEN`, at least 32 characters, environment-only
- `OPS_GUARD_JEV_EGRESS_POLICY_FILE`

Load once at startup. Invalid enabled configuration fails before listening, naming settings without their values. An empty valid policy is deny-all. Model is code-fixed `jev-1.13.0`; questions use the existing fixed rubric, instructions and menu. No deploy, gateway change, credential provisioning, or shared local-judge API change is included.

Endpoint identity is HTTPS scheme, lowercase hostname, effective port and exact path. Reject userinfo, query, fragment, malformed path/port, and identities outside the independently configured allowlist. Normal certificate verification is required. Ignore environment proxies, follow no redirects, perform no automatic retries, and attach bearer credentials only to that endpoint.

### Exact-record disclosure grants

The local policy is a closed JSON object:

```json
{"schema_version":"ops-guard-jev-egress-v1","profiles":[]}
```

Cap policy at 1 MiB and 256 profiles. Reject duplicate JSON keys, profile IDs or selector pairs; unknown keys, nonfinite numbers and invalid pointers. Each profile has exactly:

- `profile_id`: ASCII identifier `[A-Za-z0-9_-]{1,64}`
- `invocation_sha256`: lowercase 64-hex SHA-256 of existing `Invocation.canonical_bytes()`
- `citation`: exactly `runbook_id`, `revision`, `content_hash`, `locator`
- `passage_sha256`: lowercase 64-hex SHA-256 of exact UTF-8 passage bytes
- `approved_leaves`: array of closed `{pointer, value}` records
- `omitted_leaves`: array of closed `{pointer, reason}` records, reason nonblank and at most 256 characters

Exact complete-invocation hash and exact citation tuple select one profile. Re-resolved human-verified revision and exact passage bytes must match its grant. Verification is not disclosure permission; this policy is not standing authorization and never consults execution authorizations. Operator-owned real policies remain private.

Pointers are canonical RFC 6901 paths rooted at `Invocation.to_json()`, with canonical zero-based array indices. Reject root pointers, duplicate paths, invalid escapes and ancestor conflicts. Partition **Invocation terminal leaves only**, not evidence. A terminal is a scalar string/bool/null/finite JSON number or an empty object/array. For nonempty objects, enumerate leaves; whole-object omission enumerates all descendants. For nonempty arrays, enumerate every terminal descendant and approve all or omit all; no nonterminal array pointer is a partition unit. Empty arrays are terminal units. No partial array omission or reindexing.

Approved and omitted records partition the source leaves exactly. Approved values equal source values using canonical, type-aware JSON equality (`true` is not `1`). All action, target and precondition leaves must be approved. `runbook_revision_hash` must be omitted, with its binding retained locally. Argument leaves can be omitted only with the operator's explicit risk-neutrality reason. That assertion is not proof: evaluation tests the resulting projection. No wildcard, regex, value range, generic pass-through, transformations, implicit dropping, or allow-all switch exists.

Missing/ambiguous profile, changed complete invocation, unknown leaves, mismatched approved values, unsupported shape, missing required leaves or passage drift produces `judge_input_rejected` with zero requests. No safe-sounding judgment is manufactured from a silently incomplete input.

### Outbound and native wire contracts

Build from scratch, using approved values only:

```json
{
  "schema_version": "ops-guard-jev-state-v1",
  "invocation": {"action":"verify","target":"n8n","arguments":{},"preconditions":[]},
  "evidence": {"passage_text":"An explicitly approved exact passage."}
}
```

This illustrates the state shape, not an operational grant. Reconstruct approved leaves without leaking omitted values or keys. An empty arguments object is a structural constant when all argument leaves are explicitly omitted. Original invocation, approval and citation bindings remain intact. Source IDs/locators/hashes, omission reasons, scripts, tokens, credentials and audit records never enter this outbound state.

Native request has exactly `model`, object `state`, and `questions`. Model is `jev-1.13.0`. Each question is exactly the current `risk_question()` object (`type: choice`, fixed instructions and fixed `criteria` menu). Production permits exactly `risk_class`. A private evaluation helper permits a nonempty unique subset, in requested order, of `risk_class`, `companion_safety`, `companion_scope`; it is not an MCP tool. No inference overrides or other fields are sent. Official contract: <https://docs.typesafe.ai/api.md>, read during planning.

Serialize once with `json.dumps(ensure_ascii=False, separators=(',', ':'), allow_nan=False)`, preserving dictionary order, then UTF-8 encode. Use those exact bytes for the request cap, HMAC and all attempted samples. Serving contract tests include complete native request/response fixtures generated from these fixed definitions, rather than assuming Jev-shaped local adapter conformance.

### Bounds, parsing and aggregation

Request and response caps are each 64 KiB. Each of three sequential **samples** has a total monotonic 10-second deadline, including bounded incremental reads; slow-drip responses cannot extend it. At most 30 seconds of network budget plus bounded local work is not a global service SLA. Stop on the first failed sample; later samples are not sent. No retry, survivor aggregation or fallback occurs.

Only HTTP 200 qualifies. Every redirect or HTTP error (including 401/402/403/422/429/529/5xx), TLS/transport failure, timeout, oversize body, duplicate-key JSON, unexpected schema or model mismatch makes the entire assessment unavailable. The response is closed `{model, answers, usage}` with exact submitted question IDs. Each answer is closed `{type, choice, probabilities, confidence}`:

- `type` equals `choice`; selected `choice` belongs to the fixed menu.
- Probabilities have exactly the menu keys, finite nonboolean values in `[0,1]`, sum within `1e-6` of one; selected option attains a maximum, allowing a tie among maxima.
- Confidence is finite, nonboolean and in `[0,1]`.
- Usage is closed `{input_tokens, output_tokens}`, each a nonnegative nonboolean integer.

Validate native confidence/distributions but do not vote with, persist, or expose them. All three responses must validate. Aggregate labels independently per question: a unique majority answers, `vote_share` is counts/3 and `agreement` is winning count/3. A three-way tie is `judge_inability` for that question; companion answers may still be answered. A malformed/failed native response invalidates all questions for that case. Return the complete companion result map for the existing full-map scorer; production persists only `risk_class`.

Use the existing six closed failure codes: projection/configured-input/size rejection → `judge_input_rejected`; timeout → `judge_timeout`; HTTP/TLS/provider failure → `judge_unavailable`; malformed/wrong-version result → `judge_invalid_output`; tie → `judge_inability`; unexpected internal error → `judge_error`. Arbitrary error or response text never crosses the adapter boundary.

### Audit and serving identity

Create a distinct closed `ops-guard-jev-projection-v1` snapshot. Status is `answered|unavailable`; unavailable alone has `failure_code`. Common fields: schema/state/rubric/prompt/menu/adapter/parser/aggregation versions; `provider: typesafe`; requested model; ordered `response_models`; endpoint identity; policy SHA-256; profile ID (null when rejected); serving fingerprint; configured sample count 3 and timeout 10000 ms; attempted/completed sample counts; ordered request HMACs; citation references. Only answered has risk class, vote shares and agreement. No fabricated temperature, weight digest or local trace UUID.

Completed means fully validated native response. Enforce `0 <= completed_samples <= attempted_samples <= 3`; response-model count equals completed samples; request-HMAC count equals attempted samples. Answered requires three validated samples. Partial provenance may survive unavailable, but never an answered aggregate. Identical request HMACs across samples are expected for identical bytes. HMAC each exact attempted body plus policy/config reference using the existing audit key; it is not proof of vendor receipt. Denied input has zero attempts and no request HMACs.

Never persist raw state, passages, native outputs, confidence, credentials or arbitrary errors in runtime audit. Run inference outside the SQLite transaction; retain atomic proposal+snapshot recording. Judge failures still permit proposal creation if required persistence succeeds; audit failure still returns no proposal/token. Old local snapshots remain readable without rewriting audit history or adding a database migration. Authorization, approval, token and execution components never inspect judge advice or eligibility.

Serving fingerprint hashes a canonical manifest of endpoint/model, canonical policy digest, projection schema, prompt/rubric/menu digest, parser/transport bounds, sampling/aggregation/failure rules, and **actual installed serving artifact hashes**, not only manually bumped versions or Git HEAD. Include a sorted path→raw SHA-256 map covering projector, adapter, transport, parser, aggregation, `judge.py` question/menu definitions, `service.py` wiring, `invocation.py` canonicalization, and pinned dependency metadata. Missing identity cannot qualify advice. Measurement records and checks the same running artifact identity.

An eligibility manifest additionally binds corpus/report/raw hashes and all required gate predicates without self-referential hashes. Credentials are excluded; rotating them alone does not invalidate evidence. Policy, endpoint, source bytes, rubric or settings changes do. Vendor model version is **declared hosted identity**, not an immutable weights digest: undisclosed vendor changes remain undetectable. Evidence is historical; no calibration, injection immunity or deterministic hosted replay claim follows.

### Measurement and #65

Run all original 256 cases with unchanged labels and gates through the **same production projector, wire parser and aggregation helper**. Six scripted local controls stay identified separately from native integration validation. All 250 live-inference corpus states are synthetic/public, not real production data. Freeze fixture grants before inference; measurement PR authors and maintainer reviewers verify every approved literal/passage against the public corpus before publishing. No real policy or secret can enter those artifacts.

Retain original denominators. Policy rejection/unavailability is a non-answer, never success or selective exclusion. Supported means projection accepted, not answered. Report class totals and mutually exclusive terminal buckets: answered, policy/input denied, transport/provider unavailable, timeout, invalid output, vote tie, internal error. Companion mixed ties make the case a tie/non-answer under the existing full-map eligibility predicate. Any per-case failure is terminal; continue subsequent cases without retry or cherry-picking repeated runs. Publish supplemental supported-domain metrics separately.

Fresh report/raw artifacts include projected public requests, validated answers/failures, code/config/corpus identities and hashes sufficient for offline score reproduction. Preserve the original full-state experiment. Correctly publishing a failed report completes measurement work but leaves #65 blocked.

#65 retains its existing closed public object and accepted host-relay residual. A future `answered` requires valid live result plus a configured matching eligibility manifest: passing authoritative semantic gates and every supplemental full-map relation, exact evaluated serving artifact/policy/endpoint/version/configuration, and validated pinned response model. Missing/mismatched provenance yields opaque unavailable; no request-path evaluation. The local Qwen reports and full-state Jev comparison do not qualify this filtered path. The provider issue itself adds no public advisory.

## Rejected alternatives

- Full state or key-name redaction: Alan selected explicit field/value disclosure grants; strings cannot be reliably scrubbed that way.
- A generic sanitization/profile language: exact invocation records bound finite approved leaves suffice.
- Implicit argument omission or partial array filtering: hides risk-bearing context and changes array meaning.
- Reusing Qwen weight/trace metadata as Jev identity: produces false provenance.
- Counting privacy refusals as correct adversarial answers or dropping them from denominators: invalidates the evaluation.
- A shared provider platform, shared local-judge API changes, or automatic fallback: unnecessary scope and a changed disclosure boundary.
- Combining provider implementation and caller-visible advice: useful serving behavior must first pass a new measurement.

## Consequences and implementation evidence

The supported invocation domain is intentionally narrow. Updating a private invocation or passage needs a new explicit disclosure grant and invalidates previous eligibility. An operator can mistakenly approve sensitive literals or incorrectly deem omissions neutral; the policy is explicit permission, not automatic secret discovery or semantic proof. Hosted disclosure cannot be undone by switching back to local mode.

Implement under `practice:spec-first` plus `rigour:property-based`: policy/partition/pointer/type equality, zero-egress rejection, exact passage binding, safe endpoints/proxies/redirects, slow-drip bounds, native schema/sample failures, truthful privacy-preserving snapshots, source fingerprint sensitivity, authenticated MCP proposal path and unchanged authorization/token outcomes. Preserve fail-closed audit behavior. Update PRODUCT/CONTEXT, README configuration, API current behavior, system flow, and architecture C4 Context plus gateway/vendor sequence diagrams with implementation; historical local ADR 0009 remains and links to this optional mode.
