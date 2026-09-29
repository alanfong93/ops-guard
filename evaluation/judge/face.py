"""The evaluation face: runs each corpus case through the actual pinned
local-judge components (issue #60).

Deterministic fixtures go through ``RequestValidator``, ``ChoiceExecutor`` /
``SamplingOrchestrator`` with a scripted ``ModelPort``, ``resolve_replay``,
and ``JevAdapter`` — never canned final responses. Live classes use the same
path with the real model port. The face returns the runner's canonical
result shape and keeps companion results (question-map relations) in a
sidecar for the supplemental full-map check.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from local_judge.adapter import JevAdapter
from local_judge.executors.choice import ChoiceExecutor
from local_judge.models import Inference, Policy, QuestionEntry, RequestEnvelope
from local_judge.ollama import OllamaModelPort, OllamaProfile
from local_judge.orchestrator import SamplingOrchestrator, resolve_replay
from local_judge.validation import ModelProfile, RequestValidator
from local_judge.errors import StructuralError

from ops_guard.judge import (
    FIXED_BASE_URL,
    FIXED_MODEL,
    FIXED_SAMPLE_COUNT,
    FIXED_TEMPERATURE,
    FIXED_TIMEOUT_MS,
    MENU,
    PROMPT_VERSION,
    RUBRIC_VERSION,
    risk_question,
)


class ScriptedModelPort:
    """A ModelPort that replays a per-case script of raw outputs."""

    def __init__(self, script: list[str]) -> None:
        self._script = list(script)
        self.consumed = 0

    def attempt(self, model, rendered_messages, inference, response_schema=None):
        from local_judge.ports import RawAttempt, TransportOutcome

        self.consumed += 1
        if self.consumed > len(self._script):
            raise AssertionError("script exhausted: case consumed more attempts than scripted")
        output = self._script[self.consumed - 1]
        # Scripts may encode transport faults symbolically.
        if output == "@timeout":
            return RawAttempt(outcome=TransportOutcome.TIMEOUT, output=None)
        if output == "@unavailable":
            return RawAttempt(outcome=TransportOutcome.UNAVAILABLE, output=None)
        return RawAttempt(outcome=TransportOutcome.OK, output=output)


def _fixed_profiles() -> dict:
    return {FIXED_MODEL: OllamaProfile(FIXED_MODEL, base_url=FIXED_BASE_URL)}


def _fixed_validator() -> RequestValidator:
    return RequestValidator(
        {
            FIXED_MODEL: ModelProfile(
                FIXED_MODEL,
                supported_inference_settings=frozenset({"sample_count", "temperature", "timeout_ms"}),
            )
        }
    )


def _fixed_inference() -> Inference:
    return Inference(
        sample_count=FIXED_SAMPLE_COUNT,
        temperature=FIXED_TEMPERATURE,
        timeout_ms=FIXED_TIMEOUT_MS,
    )


def compose_envelope(state: Mapping[str, Any], question_ids: list[str]) -> dict:
    """The fixed native v1 request for evaluation-only question maps."""
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
        "questions": {qid: risk_question() for qid in question_ids},
    }


class EvaluationFace:
    """One face instance per run; shares the model port across cases."""

    def __init__(self, port=None) -> None:
        self._port = port  # None -> the real loopback Ollama port
        self._validator = _fixed_validator()
        self._profiles = _fixed_profiles()
        self._adapter = JevAdapter(self._validator, self._profiles)
        self.sidecar: dict[str, dict] = {}
        self.failure_counts: dict[str, dict[str, int]] = {}

    def _run_request(self, envelope: RequestEnvelope, script: list[str] | None) -> dict:
        if script is not None:
            orchestrator = self._orchestrator_with(ScriptedModelPort(script))
        else:
            orchestrator = self._orchestrator_with(
                self._port if self._port is not None else OllamaModelPort(
                    self._profiles, _default_transport()
                )
            )
        results = {}
        for qid in envelope.questions:
            entry = orchestrator.run_question(envelope, qid, envelope.questions[qid].raw)
            results[qid] = entry.to_dict()
        return {"status": "completed", "results": results}

    def _orchestrator_with(self, port):
        executor = ChoiceExecutor(dict(MENU))
        from ops_guard.judge import _SchemaForwardingPort

        forwarding = _SchemaForwardingPort(port, executor.output_schema(risk_question()))
        return SamplingOrchestrator(
            forwarding,
            executor,
            versions={
                "prompt_template_version": PROMPT_VERSION,
                "output_schema_version": RUBRIC_VERSION,
                "aggregation_version": RUBRIC_VERSION,
            },
            backend="ollama",
        )

    def __call__(self, case: Mapping[str, Any]) -> dict:
        category = case.get("deterministic_category")
        if case.get("case_class") == "deterministic":
            return self._deterministic(case, category)
        question_ids = list(case.get("question_ids") or [case.get("question_id")])
        try:
            envelope = self._validator.parse(compose_envelope(case["state"], question_ids))
        except StructuralError as error:
            return {
                "status": "rejected",
                "results": {},
                "error": {"code": error.error.code, "path": error.error.path, "message": error.error.message},
            }
        script = case.get("port_script")
        result = self._run_request(envelope, script)
        if case.get("case_class") == "metamorphic":
            self._record_full_map(case, result)
        for qid, entry in result.get("results", {}).items():
            if isinstance(entry, dict) and entry.get("status") != "answered":
                code = (entry.get("error") or {}).get("code") or entry.get("status") or "unknown"
                class_counts = self.failure_counts.setdefault(case["case_class"], {})
                class_counts[code] = class_counts.get(code, 0) + 1
        return result

    def drain_failure_counts(self) -> dict:
        totals: dict[str, int] = {}
        for counts in self.failure_counts.values():
            for code, count in counts.items():
                totals[code] = totals.get(code, 0) + count
        return {
            "non_answer_counts_by_code": dict(sorted(totals.items())),
            "by_case_class": {k: dict(sorted(v.items())) for k, v in sorted(self.failure_counts.items())},
            "note": (
                "MODEL_TIMEOUT lands here by upstream code; the pinned "
                "backend_error_rate field excludes it by contract. Counts "
                "are per question entry across all live classes."
            ),
        }

    def _record_full_map(self, case: Mapping[str, Any], result: dict) -> None:
        """Keep the aligned full result map for the supplemental check.

        For id-aligned-permutation cases the variant's results are keyed by
        the permuted IDs; the explicit inverse mapping restores the
        canonical keys so the aligned comparison is apples to apples."""
        results = json.loads(json.dumps(result.get("results", {})))
        inverse = case.get("id_permutation_inverse")
        if inverse:
            results = {inverse[pid]: entry for pid, entry in results.items()}
        self.sidecar[case["case_id"]] = {
            "results": results,
            "question_ids": list(case.get("question_ids") or [case.get("question_id")]),
        }

    def full_map_invariance(self, base_id: str, variant_id: str) -> bool:
        """True when the aligned full maps are answer-identical."""
        base = self.sidecar.get(base_id) or {}
        variant = self.sidecar.get(variant_id) or {}
        base_results = base.get("results") or {}
        variant_results = variant.get("results") or {}
        if set(base_results) != set(variant_results) or not base_results:
            return False

        def entry_answer(entry: dict):
            if not isinstance(entry, dict) or entry.get("status") != "answered":
                return ("non-answered", (entry or {}).get("status"))
            return ("answered", json.dumps(entry.get("answer"), sort_keys=True))

        return all(entry_answer(base_results[q]) == entry_answer(variant_results[q]) for q in base_results)

    # ---- deterministic categories ------------------------------------

    def _deterministic(self, case: Mapping[str, Any], category: str | None) -> dict:
        if category == "envelope_validation":
            return self._det_envelope_validation(case)
        if category == "typed_validation":
            return self._det_typed_validation(case)
        if category == "aggregate_equations":
            return self._det_answered(case)
        if category == "trace_fields":
            return self._det_answered(case)
        if category == "replay_configuration":
            return self._det_replay(case)
        if category == "adapter_refusal":
            return self._det_adapter_refusal(case)
        raise ValueError(f"unknown deterministic category: {category!r}")

    def _det_envelope_validation(self, case: Mapping[str, Any]) -> dict:
        request = compose_envelope(case["state"], [case.get("question_id", "risk_class")])
        request.update(case["malformed_override"])  # deliberate structural break
        try:
            self._validator.parse(request)
        except StructuralError as error:
            return {
                "status": "rejected",
                "results": {},
                "error": {"code": error.error.code, "path": error.error.path, "message": error.error.message},
            }
        return {"status": "completed", "results": {}}

    def _det_typed_validation(self, case: Mapping[str, Any]) -> dict:
        envelope = self._validator.parse(
            compose_envelope(case["state"], [case.get("question_id", "risk_class")])
        )
        return self._run_request(envelope, list(case["port_script"]))

    def _det_answered(self, case: Mapping[str, Any]) -> dict:
        envelope = self._validator.parse(
            compose_envelope(case["state"], [case.get("question_id", "risk_class")])
        )
        return self._run_request(envelope, list(case["port_script"]))

    def _det_replay(self, case: Mapping[str, Any]) -> dict:
        envelope = self._validator.parse(
            compose_envelope(case["state"], [case.get("question_id", "risk_class")])
        )
        first = self._run_request(envelope, list(case["port_script"]))
        entry = first["results"][case.get("question_id", "risk_class")]
        trace = entry.get("trace")
        if trace is None:
            return {"error": {"code": "REPLAY_CONFIGURATION_UNAVAILABLE"}}
        registry = {
            "prompt_templates": {PROMPT_VERSION: {"version": PROMPT_VERSION}},
            "output_schemas": {RUBRIC_VERSION: {"version": RUBRIC_VERSION}},
            "aggregations": {RUBRIC_VERSION: {"version": RUBRIC_VERSION}},
            "models": {FIXED_MODEL: {"name": FIXED_MODEL, "base_url": FIXED_BASE_URL}},
        }
        resolved = resolve_replay(_trace_from(entry), registry)
        if not hasattr(resolved, "accepted_request"):
            # RejectionResponse: the recorded configuration is not replayable.
            return {"error": {"code": resolved.error.code, "path": resolved.error.path}}
        # Replay is a new evaluation: re-run the resolved configuration.
        return self._run_request(envelope, list(case["port_script"]))

    def _det_adapter_refusal(self, case: Mapping[str, Any]) -> dict:
        jev_input = dict(case["jev_input"])
        try:
            self._adapter.convert_input(jev_input)
        except StructuralError as error:
            return {"error": {"code": error.error.code, "path": error.error.path}}
        return {"status": "completed", "results": {}}


def _trace_from(entry: dict):
    from local_judge.models import TraceRecord

    return TraceRecord.from_dict(entry["trace"])


def _default_transport():
    from local_judge.ollama import UrllibOllamaTransport
    from ops_guard.judge import ThinkDisabledTransport

    return ThinkDisabledTransport(UrllibOllamaTransport())
