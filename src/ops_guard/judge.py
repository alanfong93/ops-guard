"""The local advisory judge and its privacy-preserving audit projection
(issue #58; ADR 0009).

Consumes the pinned local-judge Python-library implementation (immutable
commit, see pyproject.toml) through this one adapter. Everything the model
sees and every inference setting is fixed in server code: the
``qwen3:8b`` loopback profile, the three-option risk menu, three sequential
samples at temperature 0 with a 10-second per-sample budget. No caller
supplies state beyond the server-composed judge state, and no caller can
override the model, rubric, menu, or settings.

The pinned ``SamplingOrchestrator`` never forwards the generated output
schema to the model port, so ``_SchemaForwardingPort`` injects
``ChoiceExecutor.output_schema(question)`` on every attempt.

``evaluate_question_map`` is the one reusable internal helper (the MCP
``propose_fix`` path calls it with exactly one fixed question ID; the S7-6
evaluation may pass distinct internal question IDs). It is not an MCP tool.

The only output is the closed ``ops-guard-risk-projection-v1`` mapping:
answered results carry the selected class, vote share, and agreement
(repeated-sample consistency — never confidence); every failure carries one
closed code. Raw state, passage text, prompts, raw attempts, exception
text, and tokens are never persisted. The projection is audit-only: no gate
reads it and no host sees it.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from local_judge.executors.choice import ChoiceExecutor
from local_judge.models import (
    Inference,
    Policy,
    QuestionEntry,
    RequestEnvelope,
    ResultEntry,
    ResultStatus,
)
from local_judge.ollama import (
    OllamaModelPort,
    OllamaProfile,
    UrllibOllamaTransport,
)
from local_judge.orchestrator import SamplingOrchestrator
from local_judge.validation import ModelProfile, RequestValidator

FIXED_MODEL = "qwen3:8b"
FIXED_BASE_URL = "http://127.0.0.1:11434"
FIXED_SAMPLE_COUNT = 3
FIXED_TEMPERATURE = 0
FIXED_TIMEOUT_MS = 10000

STATE_SCHEMA_VERSION = "ops-guard-risk-state-v1"
RUBRIC_VERSION = "ops-guard-risk-rubric-v1"
PROMPT_VERSION = "ops-guard-risk-prompt-v1"
PROJECTION_SCHEMA_VERSION = "ops-guard-risk-projection-v1"
RISK_QUESTION_ID = "risk_class"

MENU: dict[str, str] = {
    "routine": "Low-impact and readily reversible.",
    "review": "Material or context-dependent impact where a human should inspect the advisory.",
    "critical": "Plausible severe, destructive, security, availability, or irreversible impact.",
}

_RISK_INSTRUCTIONS = (
    "Classify the operational risk of the proposed invocation, given the cited "
    "verified procedure and the invocation itself. Select exactly one risk class."
)

# Closed projection failure codes (ADR 0009). No exception text is stored.
_FAILURE_BY_TERMINAL_CODE = {
    "MODEL_TIMEOUT": "judge_timeout",
    "MODEL_UNAVAILABLE": "judge_unavailable",
    "INVALID_MODEL_OUTPUT": "judge_invalid_output",
    "CONTEXT_LIMIT_EXCEEDED": "judge_input_rejected",
}
_INABILITY_FAILURE = "judge_inability"
_DEFAULT_FAILURE = "judge_error"


def risk_question() -> dict:
    """The fixed risk Choice question: same menu and instructions always."""
    return {
        "type": "choice",
        "instructions": _RISK_INSTRUCTIONS,
        "criteria": dict(MENU),
    }


def _compose_state(state: Mapping[str, Any], question_id: str) -> dict:
    """The native v1 request envelope: fixed profile/menu/policy/inference."""
    return {
        "contract_version": "v1",
        "state": state,
        "model": FIXED_MODEL,
        "policy": {"version": RUBRIC_VERSION},
        "inference": {
            "sample_count": FIXED_SAMPLE_COUNT,
            "temperature": FIXED_TEMPERATURE,
            "timeout_ms": FIXED_TIMEOUT_MS,
        },
        "questions": {question_id: risk_question()},
    }


class _SchemaForwardingPort:
    """Injects the question's sample-union schema into every attempt.

    The pinned sampler calls ``attempt(model, messages, inference)``; the
    pinned port supports ``response_schema`` but nothing passes it. This
    wrapper is the bridge (ADR 0009)."""

    def __init__(self, inner: OllamaModelPort, schema: Mapping[str, Any]) -> None:
        self._inner = inner
        self._schema = schema

    def attempt(self, model, rendered_messages, inference, response_schema=None):
        return self._inner.attempt(
            model, rendered_messages, inference, response_schema=self._schema
        )


def _resolve_model_digest(transport) -> str | None:
    """Best-effort Ollama manifest digest; provenance only, never blocking."""
    try:
        response = transport.post(
            f"{FIXED_BASE_URL.rstrip('/')}/api/show",
            {"model": FIXED_MODEL},
            2000,
        )
        if response.status_code != 200 or not response.body:
            return None
        import json

        parsed = json.loads(response.body)
        digest = parsed.get("digest") if isinstance(parsed, Mapping) else None
        return digest if isinstance(digest, str) and digest else None
    except Exception:  # noqa: BLE001 — unavailability is the documented marker path
        return None


class LocalJudge:
    """The fixed-profile advisory judge over the pinned local-judge library."""

    def __init__(
        self,
        *,
        transport=None,
        fingerprint: Callable[[Any], str] | None = None,
    ) -> None:
        self._transport = transport if transport is not None else UrllibOllamaTransport()
        self._fingerprint = fingerprint
        self._digest = _resolve_model_digest(self._transport)
        # The validator takes ModelProfile specs (settings it may honor);
        # the port takes the Ollama profile with the loopback base URL.
        self._validator = RequestValidator(
            {FIXED_MODEL: ModelProfile(FIXED_MODEL, supported_inference_settings=frozenset(
                {"sample_count", "temperature", "timeout_ms"}
            ))}
        )
        self._port = OllamaModelPort(
            {FIXED_MODEL: OllamaProfile(FIXED_MODEL, base_url=FIXED_BASE_URL)}, self._transport
        )

    def evaluate_risk(self, state: Mapping[str, Any]) -> dict:
        """The propose_fix path: exactly one fixed question ID."""
        results = self.evaluate_question_map(state, [RISK_QUESTION_ID])
        return results[RISK_QUESTION_ID]

    def evaluate_question_map(
        self, state: Mapping[str, Any], question_ids: list[str]
    ) -> dict[str, dict]:
        """Run the fixed question(s) against the composed state.

        Structural rejection maps to ``judge_input_rejected`` for every
        requested question with a null trace; per-question results map
        answered/terminal/inability outcomes onto the closed failure codes.
        This method never raises: the worst case is a typed failure.
        """
        try:
            envelopes = {
                question_id: self._validator.parse(_compose_state(state, question_id))
                for question_id in question_ids
            }
        except Exception:  # noqa: BLE001 — structural rejection is a closed failure
            return {
                question_id: self._projection(
                    status="judge_input_rejected",
                    question_id=question_id,
                    trace_id=None,
                    fingerprint=self._fingerprint_of(state, question_id),
                    state=state,
                )
                for question_id in question_ids
            }
        results: dict[str, dict] = {}
        for question_id, resolved in envelopes.items():
            try:
                entry = self._run_one(resolved, question_id)
            except Exception:  # noqa: BLE001 — the worst case is a typed failure
                results[question_id] = self._projection(
                    status="judge_error",
                    question_id=question_id,
                    trace_id=None,
                    fingerprint=self._fingerprint_of(state, question_id),
                    state=state,
                )
                continue
            results[question_id] = self._project_entry(
                entry, question_id, self._fingerprint_of(state, question_id), state
            )
        return results

    def _fingerprint_of(self, state: Mapping[str, Any], question_id: str) -> str | None:
        """Keyed fingerprint of the exact judge request: the composed state
        plus the question it was asked under (ADR 0009)."""
        if self._fingerprint is None:
            return None
        return self._fingerprint({"state": state, "question_id": question_id})

    @staticmethod
    def _citation_refs_of(state: Mapping[str, Any]) -> list[str]:
        """The immutable citation references carried by the composed state."""
        evidence = state.get("evidence") if isinstance(state, Mapping) else None
        if not isinstance(evidence, Mapping):
            return []
        return [
            f"{evidence.get('runbook_id')}@{evidence.get('revision')}",
            evidence.get("content_hash"),
            evidence.get("locator"),
        ]

    def _run_one(self, envelope: RequestEnvelope, question_id: str) -> ResultEntry:
        question = envelope.questions[question_id].raw
        executor = ChoiceExecutor(dict(MENU))
        port = _SchemaForwardingPort(self._port, executor.output_schema(question))
        orchestrator = SamplingOrchestrator(
            port,
            executor,
            versions={
                "prompt_template_version": PROMPT_VERSION,
                "output_schema_version": RUBRIC_VERSION,
                "aggregation_version": RUBRIC_VERSION,
            },
            backend="ollama",
            model_digest=self._digest,
        )
        return orchestrator.run_question(envelope, question_id, question)

    def _projection(
        self,
        *,
        status: str,
        question_id: str,
        trace_id: str | None,
        fingerprint: str | None,
        state: Mapping[str, Any],
        **extra: Any,
    ) -> dict:
        projection = {
            "schema_version": PROJECTION_SCHEMA_VERSION,
            "status": status,
            "sample_count": FIXED_SAMPLE_COUNT,
            "temperature": FIXED_TEMPERATURE,
            "timeout_ms": FIXED_TIMEOUT_MS,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "prompt_version": PROMPT_VERSION,
            "menu": dict(MENU),
            "model": FIXED_MODEL,
            "model_digest": self._digest,
            "model_digest_status": "resolved" if self._digest else "unavailable",
            "trace_id": trace_id,
            "question_id": question_id,
            "citation_refs": self._citation_refs_of(state),
            "request_fingerprint": fingerprint,
        }
        projection.update(extra)
        return projection

    def _project_entry(
        self,
        entry: ResultEntry,
        question_id: str,
        fingerprint: str | None,
        state: Mapping[str, Any],
    ) -> dict:
        if entry.status is ResultStatus.ANSWERED:
            answer = entry.answer
            return self._projection(
                status="answered",
                question_id=question_id,
                trace_id=entry.trace.trace_id,
                fingerprint=fingerprint,
                state=state,
                risk_class=answer["choice"],
                vote_share=dict(answer["vote_share"]),
                agreement=entry.agreement,
            )
        code = entry.error.code if entry.error is not None else None
        status = _FAILURE_BY_TERMINAL_CODE.get(code, _INABILITY_FAILURE if code in {
            "INSUFFICIENT_EVIDENCE",
            "AMBIGUOUS_EVIDENCE",
            "UNSUPPORTED_QUESTION",
            "AGGREGATION_TIE",
        } else _DEFAULT_FAILURE)
        return self._projection(
            status=status,
            question_id=question_id,
            trace_id=entry.trace.trace_id,
            fingerprint=fingerprint,
            state=state,
        )


def judge_state(
    *,
    invocation_json: Mapping[str, Any],
    cited_passage,
) -> dict:
    """Compose ``ops-guard-risk-state-v1`` from the validated invocation and
    the resolved verified citation (ADR 0009). Server-side only: no caller
    text or caller-controlled fields enter here."""
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "invocation": dict(invocation_json),
        "evidence": {
            "runbook_id": cited_passage.citation.runbook_id,
            "revision": cited_passage.citation.revision,
            "content_hash": cited_passage.citation.content_hash,
            "locator": cited_passage.citation.locator,
            "operation": {
                "action": cited_passage.operation_action,
                "target": cited_passage.operation_target,
            },
            "preconditions": [dict(item) for item in cited_passage.preconditions],
            "passage_text": cited_passage.passage.text,
        },
    }
