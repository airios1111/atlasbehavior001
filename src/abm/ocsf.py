"""OCSF 1.8.0 adapter: OCSF events in, normalized abm events out; abm alerts out as Detection Findings.

Inbound
    ``SOURCES`` holds one mapping table per telemetry source (the same 12 keys as
    ``compilers.common.KQL_TABLES``). Each table names the OCSF class the source is expected to
    arrive as and, for every normalized field that behaviors read, the OCSF attribute path it comes
    from. Paths use the OCSF 1.8.0 core first (including the ``ai_operation`` profile objects
    ``ai_model`` and ``message_context``), then the abm extension (``schemas/ocsf/abm-extension``),
    and fall back to OCSF's own ``unmapped`` object for the few generic enrichment flags that have
    neither. ``normalize()`` flattens one OCSF event into the field names the engine already uses.

Outbound
    ``to_detection_finding()`` turns an ``Alert`` into an OCSF Detection Finding (class 2004).
    MITRE ATLAS tactics, techniques (with their primary/secondary/precondition relationship) and
    mitigations go into the extension attribute ``atlas_mapping``. ``attacks[]`` carries the
    behavior's ATT&CK bridge techniques; ATLAS entries are added to it only on request, because
    consumers commonly treat ``attacks[]`` as ATT&CK and it cannot express the relationship.

``to_ocsf_event()`` is the reverse of ``normalize()``. It exists to generate OCSF fixtures from the
native ones and to prove the mapping is lossless; it is not a general-purpose log shipper.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from abm import __version__
from abm.telemetry import TRACED_SOURCES

Event = dict[str, Any]

OCSF_VERSION = "1.8.0"
EXTENSION = {"name": "abm", "uid": "900", "version": "0.1.0"}  # metadata.extensions[] form
PRODUCT = {"name": "ATLAS Behavior Map", "vendor_name": "atlas-behavior-map", "version": __version__}
PLACEHOLDER_TAG = "abm.placeholder_attributes"
UNKNOWN = "unknown"

# class_uid -> (class name, category_uid, caption)
CLASSES: dict[int, tuple[str, int, str]] = {
    3002: ("authentication", 3, "Authentication"),
    4002: ("http_activity", 4, "HTTP Activity"),
    6003: ("api_activity", 6, "API Activity"),
    6005: ("datastore_activity", 6, "Datastore Activity"),
    2004: ("detection_finding", 2, "Detection Finding"),
}
_ENDPOINT_KEYS = {"ip", "uid", "name", "hostname", "svc_name", "instance_uid", "interface_uid",
                  "interface_name", "domain"}
AI_ROLES = {1: "User", 2: "Assistant", 3: "Tool", 4: "Agent", 5: "Orchestrator", 6: "Retriever"}
CATEGORY_NAMES = {2: "Findings", 3: "Identity & Access Management", 4: "Network Activity",
                  6: "Application Activity"}


class OcsfMappingError(ValueError):
    """Raised when an OCSF event cannot be mapped to a known telemetry source."""


@dataclass(frozen=True)
class Flag:
    """Boolean normalized field stored as an OCSF enum value (e.g. actor.user.type_id)."""

    path: str
    true: Any
    false: Any


FieldSpec = str | Flag


@dataclass(frozen=True)
class SourceMap:
    source: str
    class_uid: int
    product: str
    fields: dict[str, FieldSpec]
    ai_role_id: int | None = None          # message_context.ai_role_id written on output
    activity_field: str | None = None      # normalized field that selects activity_id
    activity_map: dict[str, int] = field(default_factory=dict)
    verbs: bool = False                     # derive CRUD activity from the verb in activity_field
    default_activity: int = 99
    aliases: dict[str, str] = field(default_factory=dict)       # alias -> canonical field
    alt_classes: dict[int, dict[str, FieldSpec]] = field(default_factory=dict)  # class -> overrides
    alt_default_activity: dict[int, int] = field(default_factory=dict)
    database_type_id: int | None = None    # datastore_activity.database.type_id when written

    def classes(self) -> list[int]:
        return [self.class_uid, *self.alt_classes]

    def fields_for(self, class_uid: int | None) -> dict[str, FieldSpec]:
        if class_uid in self.alt_classes:
            return {**self.fields, **self.alt_classes[class_uid]}
        return self.fields


def _path(spec: FieldSpec) -> str:
    return spec.path if isinstance(spec, Flag) else spec


# ---------------------------------------------------------------------------- mapping tables
# Shared fragments. Paths are relative to the event root. "[0]" addresses the first array element.
_USER = {"principal_id": "actor.user.uid"}
_MSG = {"session_id": "message_context.uid"}
_SRC_NET = {"client_ip": "src_endpoint.ip", "client_host": "src_endpoint.hostname",
            "client_asn": "src_endpoint.autonomous_system.number"}
_HTTP = {"user_agent": "http_request.user_agent"}

SOURCES: dict[str, SourceMap] = {
    "llm_gateway": SourceMap(
        "llm_gateway", 6003, "AI Gateway", ai_role_id=1,
        activity_field="api_operation", verbs=True, default_activity=99,
        fields={
            **_USER, **_MSG, **_SRC_NET, **_HTTP,
            "model_id": "ai_model.uid",
            "model_tier": "ai_model.tier",
            "api_operation": "api.operation",
            "api_key_id": "api.token.uid",
            "client_app": "message_context.application.name",
            "input_tokens": "message_context.prompt_tokens",
            "output_tokens": "message_context.completion_tokens",
            "total_tokens": "message_context.total_tokens",
            "reasoning_tokens": "message_context.reasoning_tokens",
            "cost_usd": "message_context.cost_usd",
            "context_utilization": "message_context.context_utilization",
            "inter_arrival_s": "message_context.inter_arrival_s",
            "channel": "message_context.channel",
            "latency_ms": "duration",
            "prompt": "ai_prompt.content",
            "prompt_hash": "ai_prompt.prompt_hash",
            "user_content": "ai_prompt.user_content",
            "prompt_dialogue_turns": "ai_prompt.dialogue_turns",
            "invisible_char_count": "ai_prompt.invisible_char_count",
            "confusable_char_ratio": "ai_prompt.confusable_char_ratio",
            "suffix_perplexity": "ai_prompt.suffix_perplexity",
            "suffix_token_count": "ai_prompt.suffix_token_count",
            "request_param_keys": "ai_prompt.request_param_keys",
            "logprobs_requested": "ai_prompt.logprobs_requested",
            "completion": "ai_completion.content",
            "refused": "ai_completion.refused",
            "response_has_citations": "ai_completion.has_citations",
            "cited_unretrieved_sources": "ai_completion.cited_unretrieved_sources",
            "memorization_score": "ai_completion.memorization_score",
            "completion_link_domains": "ai_completion.link_domains",
            "completion_link_reputation": "ai_completion.link_reputation",
            "nonexistent_packages_in_completion": "ai_completion.nonexistent_package_count",
            "guardrail_verdict": "ai_guardrail.guardrail_verdict",
            "moderation_verdict": "ai_guardrail.moderation_verdict",
            "harm_score": "ai_guardrail.harm_score",
            "jailbreak_corpus_match": "ai_guardrail.jailbreak_corpus_match",
            "workload_registered": "unmapped.workload_registered",
        },
        # Gateways that log as HTTP Activity: no api object (it is a cloud-profile attribute there)
        alt_classes={4002: {"api_operation": "unmapped.api_operation",
                            "api_key_id": "unmapped.api_key_id"}},
        alt_default_activity={4002: 6},  # Post
    ),
    "inference_gateway": SourceMap(
        "inference_gateway", 6003, "Model Inference Gateway",
        default_activity=99,
        fields={
            **_USER, **_HTTP,
            "client_ip": "src_endpoint.ip",
            "session_id": "actor.session.uid",
            "principal_type": "actor.user.type",
            "model_id": "ai_model.uid",
            "environment": "ai_model.environment",
            "endpoint": "api.service.name",
            "request_id": "api.request.uid",
            "request_path": "http_request.url.path",
            "status_code": "http_response.code",
            "camera_id": "device.uid",
            "client_app": "message_context.application.name",
            "request_param_keys": "ai_inference.request_param_keys",
            "input_hash": "ai_inference.input_hash",
            "input_modality": "ai_inference.input_modality",
            "input_embedding_norm": "ai_inference.input_embedding_norm",
            "input_similarity_to_prev": "ai_inference.input_similarity_to_prev",
            "input_quality_score": "ai_inference.input_quality_score",
            "decision_margin": "ai_inference.decision_margin",
            "predicted_class": "ai_inference.predicted_class",
            "predicted_label": "ai_inference.predicted_label",
            "return_confidence": "ai_inference.return_confidence",
            "prediction_changed_by_trigger": "ai_inference.prediction_changed_by_trigger",
            "decompression_ratio": "ai_inference.decompression_ratio",
            "fuzzy_hash_cluster": "ai_inference.fuzzy_hash_cluster",
            "is_timeout": "ai_inference.is_timeout",
            "task": "ai_inference.task",
            "check_type": "ai_inference.check_type",
            "speaker_consent_on_file": "ai_inference.speaker_consent_on_file",
            "speaker_is_protected_person": "ai_inference.speaker_is_protected_person",
            "file_sha256": "ai_inference.file_sha256",
            "via_app_gateway": "ai_inference.via_app_gateway",
            "adv_detector_score": "ai_guardrail.adv_detector_score",
            "patch_detector_score": "ai_guardrail.patch_detector_score",
            "trigger_detector_score": "ai_guardrail.trigger_detector_score",
            "deepfake_score": "ai_guardrail.deepfake_score",
        },
        alt_classes={4002: {"request_id": "http_request.uid",
                            "endpoint": "message_context.service.name"}},
        alt_default_activity={4002: 6},
    ),
    "llm_retrieval": SourceMap(
        "llm_retrieval", 6005, "RAG Retriever", ai_role_id=6,
        default_activity=4,  # Query
        fields={
            **_USER, **_MSG,
            "query": "query_info.query_string",
            "query_id": "query_info.uid",
            "doc_id": "ai_context_record.uid",
            "retrieved_content": "ai_context_record.content",
            "raw_html": "ai_context_record.raw_html",
            "source_uri": "ai_context_record.url.url_string",
            "source_domain": "ai_context_record.url.domain",
            "source_trust": "ai_context_record.source_trust",
            "source_type": "ai_context_record.source_type",
            "source_system": "ai_context_record.source_system",
            "source_domain_age_days": "ai_context_record.source_domain_age_days",
            "doc_sensitivity": "ai_context_record.doc_sensitivity",
            "caller_clearance": "ai_context_record.caller_clearance",
            "tenant_mismatch": "ai_context_record.tenant_mismatch",
        },
    ),
    "vector_store": SourceMap(
        "vector_store", 6005, "Vector Store", database_type_id=7,  # Vector
        activity_field="operation", default_activity=99,
        activity_map={"query": 4, "search": 4, "upsert": 5, "insert": 5, "write": 5, "export": 1,
                      "read": 1, "delete": 7, "list": 8, "create": 6, "update": 2},
        fields={
            **_USER,
            "operation": "api.operation",
            "collection": "database.name",
            "doc_id": "ai_context_record.uid",
            "content": "ai_context_record.content",
            "source_trust": "ai_context_record.source_trust",
            "near_duplicate_score": "ai_context_record.near_duplicate_score",
            "top_k": "ai_context_record.top_k",
            "records_returned": "ai_context_record.records_returned",
            "uploader_id": "ai_context_record.uploader_uid",
        },
    ),
    "agent_memory": SourceMap(
        "agent_memory", 6005, "Agent Memory Store", ai_role_id=4,
        activity_field="operation", default_activity=99,
        activity_map={"write": 5, "history_write": 5, "read": 1, "delete": 7, "update": 2},
        fields={
            **_USER,
            "operation": "api.operation",
            "agent_id": "message_context.application.uid",
            "conversation_id": "message_context.name",
            "memory_text": "ai_context_record.content",
            "actor_is_conversation_owner": "ai_context_record.actor_is_conversation_owner",
        },
    ),
    "agent_runtime": SourceMap(
        "agent_runtime", 6003, "Agent Runtime", ai_role_id=3,
        activity_field="event_type", default_activity=99,
        fields={
            **_USER, **_MSG,
            "actor_is_admin": Flag("actor.user.type_id", 2, 1),  # Admin / User
            "agent_id": "message_context.application.uid",
            "cost_usd": "message_context.cost_usd",
            "inter_arrival_s": "message_context.inter_arrival_s",
            "event_type": "metadata.event_code",
            "url": "http_request.url.url_string",
            "request_bytes": "http_request.length",
            "destination_domain": "dst_endpoint.domain",
            "tool_name": "ai_tool_call.tool_name",
            "tool_args": "ai_tool_call.tool_args",
            "tool_output": "ai_tool_call.tool_output",
            "tool_category": "ai_tool_call.tool_category",
            "tool_risk": "ai_tool_call.tool_risk",
            "tool_in_scope": "ai_tool_call.tool_in_scope",
            "human_approved": "ai_tool_call.human_approved",
            "initiated_by_user": "ai_tool_call.initiated_by_user",
            "acting_above_user_privilege": "ai_tool_call.acting_above_user_privilege",
            "context_has_untrusted_content": "ai_tool_call.context_has_untrusted_content",
            "is_secret_read": "ai_tool_call.is_secret_read",
            "is_external_egress": "ai_tool_call.is_external_egress",
            "records_returned": "ai_tool_call.records_returned",
            "attachment_count": "ai_tool_call.attachment_count",
            "recipient_external": "ai_tool_call.recipient_external",
            "destination_allowlisted": "ai_tool_call.destination_allowlisted",
            "page_trust": "ai_tool_call.page_trust",
            "target_category": "ai_tool_call.target_category",
            "change_target": "ai_tool_call.change_target",
            "cloud_api": "ai_tool_call.cloud_api",
            "file_path": "ai_tool_call.file_path",
            "host_id": "device.uid",
            "config_key": "resources[0].name",
            "change_origin": "unmapped.change_origin",
            "trace_id": "trace.uid",
            "span_id": "trace.span.uid",
            "parent_span_id": "trace.span.parent_uid",
            "operation": "trace.span.operation",
            "input_span_ids": "ai_tool_call.input_span_ids",
            "input_origin": "ai_tool_call.input_origin",
            "source_trust": "ai_tool_call.source_trust",
            "tool_class": "ai_tool_call.tool_class",
        },
    ),
    "mcp_gateway": SourceMap(
        "mcp_gateway", 6003, "MCP Gateway", ai_role_id=3,
        activity_field="event_type", default_activity=99,
        activity_map={"tool_registered": 1, "tool_manifest_change": 3, "tool_removed": 4},
        fields={
            **_MSG,
            "agent_id": "message_context.application.uid",
            "server_id": "message_context.service.uid",
            "event_type": "metadata.event_code",
            "tool_name": "ai_tool_call.tool_name",
            "tool_description": "ai_tool_call.desc",
            "auth_type": "ai_tool_call.server_auth_type",
            "server_in_agent_manifest": "ai_tool_call.server_in_agent_manifest",
            "server_first_seen_for_agent": "ai_tool_call.server_first_seen_for_agent",
            "manifest_hash_approved": "ai_tool_call.manifest_hash_approved",
            "name_similarity_to_approved": "ai_tool_call.name_similarity_to_approved",
            "publisher_verified": "ai_tool_call.publisher_verified",
            "package_age_days": "ai_tool_call.package_age_days",
            "server_scan_verdict": "ai_tool_call.server_scan_verdict",
            "trace_id": "trace.uid",
            "span_id": "trace.span.uid",
            "parent_span_id": "trace.span.parent_uid",
            "mcp_method": "api.operation",
            "tool_class": "ai_tool_call.tool_class",
        },
    ),
    "model_registry": SourceMap(
        "model_registry", 6003, "Model Registry",
        activity_field="event_type", default_activity=99,
        activity_map={"model_import": 1, "model_register": 1, "artifact_download": 2,
                      "model_load": 2, "weights_update": 3, "model_delete": 4},
        fields={
            **_USER,
            "model_id": "ai_model.uid",
            "environment": "ai_model.environment",
            "event_type": "metadata.event_code",
            "training_job_id": "ai_training.job_uid",
            "artifact_id": "ai_artifact.uid",
            "artifact_type": "ai_artifact.artifact_type",
            "digest_match": "ai_artifact.digest_match",
            "signature_status": "ai_artifact.signature_status",
            "publisher": "ai_artifact.publisher",
            "publisher_allowlisted": "ai_artifact.publisher_allowlisted",
            "publisher_similarity_to_allowlisted": "ai_artifact.publisher_similarity_to_allowlisted",
            "source_hub": "ai_artifact.source_hub",
            "source_repo": "ai_artifact.source_repo",
            "size_gb": "ai_artifact.size_gb",
            "unsafe_opcode_count": "ai_artifact.unsafe_opcode_count",
            "malware_signature_hits": "ai_artifact.malware_signature_hits",
            "architecture_hash_match": "ai_artifact.architecture_hash_match",
            "backdoor_anomaly_index": "ai_artifact.backdoor_anomaly_index",
            "trigger_asr": "ai_artifact.trigger_asr",
            "accuracy_drop_pct": "ai_artifact.accuracy_drop_pct",
            "artifact_name": "ai_artifact.name",
            "latest_scan_status": "ai_artifact.scan_status",
            "name_matches_approved_artifact": "ai_artifact.name_matches_approved",
            "registrant_in_owner_group": "ai_artifact.registrant_in_owner_group",
        },
    ),
    "ml_workspace": SourceMap(
        "ml_workspace", 6003, "ML Workspace",
        activity_field="event_type", default_activity=99,
        activity_map={"package_install": 1, "model_load": 2, "model_card_view": 2,
                      "artifact_download": 2},
        fields={
            **_USER,
            "workspace_id": "api.service.uid",
            "event_type": "metadata.event_code",
            "artifact_id": "ai_artifact.uid",
            "package_name": "ai_artifact.name",
            "artifact_classification": "ai_artifact.classification",
            "environment": "ai_artifact.environment",
            "package_age_days": "ai_artifact.package_age_days",
            "typosquat_score": "ai_artifact.typosquat_score",
            "suggested_by_llm": "ai_artifact.suggested_by_llm",
            "child_process": "ai_artifact.load_child_process",
        },
    ),
    "training_pipeline": SourceMap(
        "training_pipeline", 6003, "Training Pipeline",
        activity_field="event_type", default_activity=99,
        activity_map={"dataset_import": 1, "dataset_ingest": 1, "batch_ingest": 1,
                      "training_job_submit": 1, "finetune_start": 1, "dataset_download": 2},
        fields={
            **_USER,
            "event_type": "metadata.event_code",
            "job_id": "ai_training.job_uid",
            "pipeline_id": "ai_training.pipeline_uid",
            "batch_id": "ai_training.batch_uid",
            "dataset_id": "ai_training.dataset_uid",
            "dataset_sensitivity": "ai_training.dataset_sensitivity",
            "dataset_provenance_verified": "ai_training.dataset_provenance_verified",
            "provenance_signed": "ai_training.provenance_signed",
            "checksum_match": "ai_training.checksum_match",
            "record_count": "ai_training.record_count",
            "distribution_shift_psi": "ai_training.distribution_shift_psi",
            "label_disagreement_rate": "ai_training.label_disagreement_rate",
            "contributor_id": "ai_training.contributor_uid",
            "contributor_type": "ai_training.contributor_type",
            "source_external": "ai_training.source_external",
            "principal_in_dataset_acl": "ai_training.principal_in_dataset_acl",
            "requested_gpu_hours": "ai_training.requested_gpu_hours",
            "budget_approved": "ai_training.budget_approved",
            "target_environment": "ai_training.target_environment",
        },
    ),
    "cloud_audit": SourceMap(
        "cloud_audit", 6003, "Cloud Audit Log",
        activity_field="operation", verbs=True, default_activity=99,
        activity_map={"agent_deploy": 1, "container_deploy": 1},
        fields={
            **_USER,
            "operation": "api.operation",
            "event_type": "metadata.event_code",
            "principal_role": "actor.user.groups[0].name",
            "agent_name": "resources[0].name",
            "resource_id": "resources[0].uid",
            "resource_type": "resources[0].type",
            "image": "ai_artifact.name",
            "image_signature_status": "ai_artifact.signature_status",
            "workload_type": "ai_artifact.workload_type",
            "deployer_in_approved_group": "unmapped.deployer_in_approved_group",
            "scope": "unmapped.scope",
        },
    ),
    "identity": SourceMap(
        "identity", 3002, "Identity Provider",
        activity_field="event_type", default_activity=1,  # Logon
        activity_map={"sign_in": 1, "signin": 1, "logon": 1, "sign_out": 2, "logoff": 2},
        fields={
            "principal_id": "user.uid",
            "account_id": "user.account.uid",
            "event_type": "metadata.event_code",
            "auth_method": "auth_protocol",
            "client_app": "actor.app_name",
            "ip": "src_endpoint.ip",
            "client_asn": "src_endpoint.autonomous_system.number",
            "device_id": "device.uid",
            "token_id": "authentication_token.uid",
            "token_type": "authentication_token.type",
            "device_fingerprint": "unmapped.device_fingerprint",
            "sign_in_asn_seen_before": "unmapped.sign_in_asn_seen_before",
        },
        aliases={"asn": "client_asn"},
    ),
}

# ---------------------------------------------------------------------------- path helpers
_MISSING = object()


def _split(path: str) -> list[tuple[str, bool]]:
    return [(p[:-3], True) if p.endswith("[0]") else (p, False) for p in path.split(".")]


def get_path(ev: Any, path: str, default: Any = _MISSING) -> Any:
    cur = ev
    for name, idx in _split(path):
        if not isinstance(cur, dict) or name not in cur:
            return default
        cur = cur[name]
        if idx:
            if not isinstance(cur, list) or not cur:
                return default
            cur = cur[0]
    return cur


def set_path(ev: dict[str, Any], path: str, value: Any) -> None:
    parts = _split(path)
    cur: Any = ev
    for i, (name, idx) in enumerate(parts):
        last = i == len(parts) - 1
        if idx:
            lst = cur.setdefault(name, [{}])
            if last:
                lst[0] = value
                return
            cur = lst[0]
        elif last:
            cur[name] = value
        else:
            cur = cur.setdefault(name, {})


def _leaf_paths(obj: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaf_paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        yield from _leaf_paths(obj[0], f"{prefix}[0]")
    else:
        yield prefix


# ---------------------------------------------------------------------------- time
def _parse_ts(v: Any) -> datetime | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return datetime.fromtimestamp(float(v), tz=UTC)
    if isinstance(v, str):
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _ms(dt: datetime) -> int:
    return round(dt.timestamp() * 1000)


def _iso_from_ms(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=UTC)
    if ms % 1000:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------- inbound
def detect_source(ev: Event) -> str:
    """metadata.log_name (or log_source) naming an abm source wins; otherwise the source whose
    mapped attribute paths cover most of the event's attributes (ties: table order)."""
    meta = ev.get("metadata") or {}
    for key in ("log_name", "log_source"):
        if meta.get(key) in SOURCES:
            return meta[key]
    uid = ev.get("class_uid")
    leaves = set(_leaf_paths({k: v for k, v in ev.items() if k != "metadata"})) - _placeholders(ev)
    role = get_path(ev, "message_context.ai_role_id", None)
    best, best_score = None, 0.0
    for name, spec in SOURCES.items():
        if uid not in spec.classes():
            continue
        score = len(leaves & {_path(p) for p in spec.fields_for(uid).values()})
        if score and role is not None and role == spec.ai_role_id:
            score += 0.5  # the AI role (User, Tool, Retriever, Agent) breaks ties between sources
        if score > best_score:
            best, best_score = name, score
    if best is None:
        raise OcsfMappingError(
            f"cannot map OCSF event (class_uid={uid!r}) to an abm source; set metadata.log_name "
            f"to one of {sorted(SOURCES)} or pass --ocsf-source")
    return best


def _placeholders(ev: Event) -> set[str]:
    for tag in (ev.get("metadata") or {}).get("tags") or []:
        if isinstance(tag, dict) and tag.get("name") == PLACEHOLDER_TAG:
            return set(tag.get("values") or [])
    return set()


def normalize(ev: Event, source: str | None = None) -> Event:
    """Flatten one OCSF event into the normalized field names behaviors read."""
    if not isinstance(ev, dict):
        raise OcsfMappingError(f"OCSF event must be a JSON object, got {type(ev).__name__}")
    src = source or detect_source(ev)
    if src not in SOURCES:
        raise OcsfMappingError(f"unknown source '{src}' (known: {sorted(SOURCES)})")
    spec = SOURCES[src]
    uid = ev.get("class_uid")
    if uid not in spec.classes():
        raise OcsfMappingError(f"source '{src}' expects class_uid {spec.classes()}, got {uid!r}")
    skip = _placeholders(ev)
    out: Event = {}
    if "time_dt" in ev:
        out["timestamp"] = ev["time_dt"]
    elif isinstance(ev.get("time"), int):
        out["timestamp"] = _iso_from_ms(ev["time"])
    for name, fs in spec.fields_for(uid).items():
        p = _path(fs)
        if p in skip:
            continue
        v = get_path(ev, p)
        if v is _MISSING or v is None:
            continue
        if isinstance(fs, Flag):
            if v == fs.true:
                out[name] = True
            elif v == fs.false:
                out[name] = False
            continue
        out[name] = v
    for k, v in (ev.get("unmapped") or {}).items():
        if k not in out and f"unmapped.{k}" not in skip:
            out[k] = v
    for alias, canonical in spec.aliases.items():
        if canonical in out and alias not in out:
            out[alias] = out[canonical]
    # A root span has parent_span_id null. OCSF omits null attributes, so a traced span with a
    # trace but no trace.span.parent_uid is a root: restore the explicit null the span contract
    # requires (abm.telemetry), or the provenance graph reports the field as missing.
    if src in TRACED_SOURCES and "span_id" in out and "parent_span_id" not in out:
        out["parent_span_id"] = None
    return out


def load_ocsf_events(path: Path, source: str | None = None) -> list[Event]:
    """Read OCSF events (JSON Lines, or one JSON array) and normalize them."""
    text = path.read_text(encoding="utf-8")
    raw: list[Any] = []
    if text.lstrip().startswith("["):
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}: invalid JSON: {e}") from e
    else:
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                raw.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: invalid JSON: {e}") from e
    out = []
    for i, ev in enumerate(raw, 1):
        try:
            out.append(normalize(ev, source))
        except OcsfMappingError as e:
            raise OcsfMappingError(f"{path}: event {i}: {e}") from e
    return out


def read_ocsf(path: Path) -> list[Event]:
    """Raw OCSF events from a JSON Lines file or JSON array (no normalization)."""
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith("["):
        return json.loads(text)
    return [json.loads(x) for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]


# ---------------------------------------------------------------------------- native -> OCSF
_READ = ("list", "get", "read", "retrieve", "search", "query", "describe", "export", "download")
_DELETE = ("delete", "remove", "purge")
_UPDATE = ("update", "patch", "modify", "set", "put", "edit")
_CREATE = ("create", "add", "insert", "register", "import", "upload", "deploy")


def _verb_activity(value: str) -> int | None:
    v = value.lower()
    for words, act in ((_DELETE, 4), (_UPDATE, 3), (_CREATE, 1), (_READ, 2)):
        if any(w in v for w in words):
            return act
    return None


def _activity_value(spec: SourceMap, ev: Event) -> str | None:
    for f in (spec.activity_field, "event_type"):
        if f and isinstance(ev.get(f), str):
            return ev[f]
    return None


def _activity(spec: SourceMap, ev: Event, class_uid: int) -> int:
    if class_uid in spec.alt_default_activity:
        return spec.alt_default_activity[class_uid]
    val = _activity_value(spec, ev)
    if val is not None:
        if val in spec.activity_map:
            return spec.activity_map[val]
        if spec.verbs and CLASSES[class_uid][0] == "api_activity":
            act = _verb_activity(val)
            if act is not None:
                return act
    return spec.default_activity


_ACTIVITY_CAPTIONS = {
    "api_activity": {0: "Unknown", 1: "Create", 2: "Read", 3: "Update", 4: "Delete", 99: "Other"},
    "datastore_activity": {0: "Unknown", 1: "Read", 2: "Update", 3: "Connect", 4: "Query", 5: "Write",
                           6: "Create", 7: "Delete", 8: "List", 9: "Encrypt", 10: "Decrypt", 99: "Other"},
    "http_activity": {0: "Unknown", 1: "Connect", 2: "Delete", 3: "Get", 4: "Head", 5: "Options",
                      6: "Post", 7: "Put", 8: "Trace", 9: "Patch", 99: "Other"},
    "authentication": {0: "Unknown", 1: "Logon", 2: "Logoff", 99: "Other"},
}


def to_ocsf_event(ev: Event, source: str, class_uid: int | None = None) -> Event:
    """Wrap one normalized event as an OCSF event of the source's class (lossless for mapped
    fields; fields without a mapping are kept under ``unmapped``; null values are dropped)."""
    spec = SOURCES[source]
    cuid = class_uid or spec.class_uid
    if cuid not in spec.classes():
        raise OcsfMappingError(f"source '{source}' cannot be written as class {cuid}")
    cname, cat, caption = CLASSES[cuid]
    fields = spec.fields_for(cuid)
    act = _activity(spec, ev, cuid)
    act_name = _ACTIVITY_CAPTIONS[cname].get(act, "Other")
    if act == 99 and _activity_value(spec, ev) is not None:
        act_name = str(_activity_value(spec, ev))
    profiles = []
    out: Event = {
        "class_uid": cuid, "class_name": caption, "category_uid": cat,
        "category_name": CATEGORY_NAMES[cat], "activity_id": act, "activity_name": act_name,
        "type_uid": cuid * 100 + act, "type_name": f"{caption}: {act_name}",
        "severity_id": 1, "severity": "Informational",
    }
    ts = _parse_ts(ev.get("timestamp"))
    if ts is not None:
        out["time"] = _ms(ts)
        if isinstance(ev.get("timestamp"), str):
            out["time_dt"] = ev["timestamp"]
            profiles.append("datetime")
    out["metadata"] = {"version": OCSF_VERSION, "log_name": source,
                       "product": {"name": spec.product, "vendor_name": "abm-fixtures"},
                       "extensions": [dict(EXTENSION)]}
    unmapped: dict[str, Any] = {}
    for k, v in ev.items():
        if k == "timestamp":
            continue
        if k in spec.aliases:
            canonical = spec.aliases[k]
            if canonical in ev:
                unmapped[k] = v
                continue
            k = canonical
        if k not in fields:
            unmapped[k] = v
            continue
        if v is None:
            continue
        fs = fields[k]
        if isinstance(fs, Flag):
            set_path(out, fs.path, fs.true if v else fs.false)
        else:
            set_path(out, fs, v)
    if unmapped:
        out.setdefault("unmapped", {}).update(unmapped)
    placeholders = _complete(out, spec, cname, ev)
    if cname in ("api_activity", "datastore_activity") and ("ai_model" in out or "message_context" in out):
        profiles.append("ai_operation")
    if profiles:
        out["metadata"]["profiles"] = profiles
    if placeholders:
        out["metadata"]["tags"] = [{"name": PLACEHOLDER_TAG, "values": sorted(placeholders)}]
    return out


def _complete(out: Event, spec: SourceMap, cname: str, ev: Event) -> set[str]:
    """Fill attributes OCSF requires but the source did not observe. Values that are not derived
    from the event are recorded as placeholders (metadata.tags) so normalize() ignores them."""
    ph: set[str] = set()

    def fill(path: str, value: Any) -> None:
        if get_path(out, path) is _MISSING:
            set_path(out, path, value)
            ph.add(path)

    if spec.ai_role_id is not None:
        set_path(out, "message_context.ai_role_id", spec.ai_role_id)
        set_path(out, "message_context.ai_role", AI_ROLES[spec.ai_role_id])
    mc = out.get("message_context")
    if isinstance(mc, dict) and not ({"application", "service"} & set(mc)):
        fill("message_context.service.name", spec.product)
    am = out.get("ai_model")
    if isinstance(am, dict):
        if "name" not in am and "uid" in am:
            am["name"] = am["uid"]  # derived: the model identifier is the best name available
        fill("ai_model.name", UNKNOWN)
        fill("ai_model.ai_provider", UNKNOWN)
    if cname in ("api_activity", "datastore_activity"):
        actor = out.get("actor") or {}
        if not ({"process", "user", "invoked_by", "session", "app_name", "app_uid"} & set(actor)):
            fill("actor.app_name", spec.product)
    if cname in ("api_activity", "datastore_activity") or "src_endpoint" in out:
        if not (_ENDPOINT_KEYS & set(out.get("src_endpoint") or {})):
            fill("src_endpoint.svc_name", spec.source)
    if cname == "datastore_activity" and not ({"database", "databucket", "table"} & set(out)):
        fill("database.name", spec.product)
    if cname == "http_activity" and not ({"http_request", "http_response"} & set(out)):
        fill("http_request.http_method", "POST")
    if cname == "authentication" and not ({"service", "dst_endpoint"} & set(out)):
        fill("service.name", spec.product)
    if cname == "api_activity":
        op = _activity_value(spec, ev) or (ev["tool_name"] if isinstance(ev.get("tool_name"), str)
                                           else UNKNOWN)
        fill("api.operation", op)
    if cname == "authentication" and "user" not in out:
        fill("user.name", UNKNOWN)
    for holder in ("actor.user", "user"):
        u = get_path(out, holder)
        if isinstance(u, dict) and not ({"account", "name", "uid"} & set(u)):
            fill(f"{holder}.name", UNKNOWN)
    if cname == "authentication":
        if "auth_protocol" in out:
            out["auth_protocol_id"] = 99  # Other: the source's method name stays in auth_protocol
    if "device" in out:
        out["device"].setdefault("type_id", 0)
    if "database" in out:
        out["database"].setdefault("type_id", spec.database_type_id or 0)
    qi = out.get("query_info")
    if isinstance(qi, dict):
        fill("query_info.query_string", UNKNOWN)
        if not ({"name", "uid"} & set(qi)):
            fill("query_info.name", UNKNOWN)
    for holder in ("ai_context_record.url", "http_request.url"):
        u = get_path(out, holder)
        if isinstance(u, dict) and not ({"url_string", "path"} & set(u)):
            fill(f"{holder}.url_string", UNKNOWN)
    user = get_path(out, "actor.user")
    if isinstance(user, dict) and "type" in user and "type_id" not in user:
        user["type_id"] = {"human": 1, "user": 1, "admin": 2, "system": 3, "service": 4}.get(
            str(user["type"]).lower(), 99)
    token = get_path(out, "api.token")
    if isinstance(token, dict):
        token.setdefault("type_id", 7)  # API Token
    return ph


# ---------------------------------------------------------------------------- outbound findings
SEVERITY_IDS = {"low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_CAPTIONS = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
CONFIDENCE_IDS = {"low": 1, "medium": 2, "high": 3, "critical": 3}
CONFIDENCE_CAPTIONS = {1: "Low", 2: "Medium", 3: "High"}
ANALYTIC_TYPES = {"signature": (8, "Regular Expressions"), "field_match": (1, "Rule"),
                  "windowed_threshold": (3, "Statistical")}
ANALYTIC_STATES = {"stable": (1, "Active"), "test": (3, "Experimental"),
                   "experimental": (3, "Experimental"), "deprecated": (2, "Suppressed")}
_ATLAS_SUB_RE = re.compile(r"^AML\.T\d{4}\.\d{3}$")
_FINDING_NS = uuid.UUID("6f1c2d0e-7a3b-5c4d-9e8f-a1b2c3d4e5f6")


def _atlas_url(atlas_id: str) -> str:
    kind = ("tactics" if ".TA" in atlas_id else "mitigations" if ".M" in atlas_id else "techniques")
    return f"https://atlas.mitre.org/{kind}/{atlas_id}"


def _entity(atlas_id: str, catalog: Any) -> dict[str, Any]:
    e: dict[str, Any] = {"uid": atlas_id, "src_url": _atlas_url(atlas_id)}
    if catalog is not None and catalog.has(atlas_id):
        e["name"] = catalog.name(atlas_id)
    return e


def _attack_entry(tid: str) -> dict[str, Any]:
    if "." in tid and not tid.startswith("AML."):
        return {"technique": {"uid": tid.split(".")[0]}, "sub_technique": {"uid": tid}}
    return {"technique": {"uid": tid}}


def finding_uid(d: dict[str, Any]) -> str:
    key = json.dumps([d["behavior_id"], d.get("window_start"), d.get("context"), d.get("technique")],
                     sort_keys=True, default=str)
    return str(uuid.uuid5(_FINDING_NS, key))


def to_detection_finding(alert: Any, behavior: Any = None, catalog: Any = None, *,
                         response: list[Any] | None = None, atlas_in_attacks: bool = False,
                         now: datetime | None = None) -> Event:
    """OCSF 1.8.0 Detection Finding (class 2004) for one abm alert."""
    d = alert.to_dict() if hasattr(alert, "to_dict") else dict(alert)
    ws = d.get("window_start")
    ts = _parse_ts(ws) or now or datetime.now(tz=UTC)
    sev = SEVERITY_IDS.get(d["severity"], 0)
    uid = finding_uid(d)
    ctx = d.get("context") or {}

    techniques: list[dict[str, Any]]
    if behavior is not None:
        techniques = [{**_entity(t.id, catalog), "atlas_relationship": t.relationship}
                      for t in behavior.atlas.techniques]
    else:
        techniques = [{**_entity(d["technique"], catalog), "atlas_relationship": "primary"}]
    atlas: dict[str, Any] = {
        "technique": _entity(d["technique"], catalog),
        "techniques": techniques,
        "tactics": [_entity(t, catalog) for t in d.get("tactics") or []],
    }
    if catalog is not None and getattr(catalog, "version", ""):
        atlas["version"] = str(catalog.version)
    if behavior is not None and behavior.countermeasures.mitigations:
        atlas["mitigations"] = [_entity(m, catalog) for m in behavior.countermeasures.mitigations]

    analytic: dict[str, Any] = {"uid": d["behavior_id"], "name": d["name"]}
    if behavior is not None:
        analytic["type_id"], analytic["type"] = ANALYTIC_TYPES[behavior.detection.logic]
        analytic["state_id"], analytic["state"] = ANALYTIC_STATES[behavior.status.value]
        analytic["category"] = behavior.log_source
    else:
        analytic["type_id"], analytic["type"] = 0, "Unknown"

    info: dict[str, Any] = {
        "uid": uid, "title": d["name"], "analytic": analytic,
        "types": [atlas["technique"].get("name", d["technique"])],
        "first_seen_time": _ms(ts), "last_seen_time": _ms(ts),
    }
    if behavior is not None:
        info["desc"] = " ".join(behavior.description.split())
        info["data_sources"] = sorted({s.source for s in behavior.telemetry.required})

    attacks = [_attack_entry(t) for t in (behavior.attack_bridge if behavior is not None else [])]
    if atlas_in_attacks:
        for t in techniques:
            ref = {k: t[k] for k in ("uid", "name", "src_url") if k in t}
            if _ATLAS_SUB_RE.match(t["uid"]):
                entry: dict[str, Any] = {"technique": _entity(t["uid"].rsplit(".", 1)[0], catalog),
                                         "sub_technique": ref}
            else:
                entry = {"technique": ref}
            entry["tactics"] = atlas["tactics"]
            if "version" in atlas:
                entry["version"] = atlas["version"]
            attacks.append(entry)

    f: Event = {
        "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2,
        "category_name": "Findings", "activity_id": 1, "activity_name": "Create",
        "type_uid": 200401, "type_name": "Detection Finding: Create",
        "severity_id": sev, "severity": SEVERITY_CAPTIONS.get(sev, "Unknown"),
        "status_id": 1, "status": "New", "is_alert": True,
        "time": _ms(ts),
        "message": f"[{d['behavior_id']}] {d['name']}",
        "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT), "event_code": d["behavior_id"],
                     "uid": uid, "extensions": [dict(EXTENSION)]},
        "finding_info": info,
        "atlas_mapping": atlas,
        "evidences": [{"data": {"context": ctx, "metrics": d.get("metrics") or {},
                                "matched": d.get("evidence") or [], "window_start": ws}}],
    }
    if isinstance(ws, str):
        f["time_dt"] = ws
        f["metadata"]["profiles"] = ["datetime"]
    if behavior is not None:
        cid = CONFIDENCE_IDS[behavior.confidence.value]
        f["confidence_id"], f["confidence"] = cid, CONFIDENCE_CAPTIONS[cid]
    if attacks:
        f["attacks"] = attacks
    actor: dict[str, Any] = {}
    if isinstance(ctx.get("principal_id"), str):
        actor["user"] = {"uid": ctx["principal_id"]}
    if isinstance(ctx.get("session_id"), str):
        actor["session"] = {"uid": ctx["session_id"]}
    if actor:
        f["actor"] = actor
    if isinstance(ctx.get("model_id"), str):
        f["ai_model"] = {"uid": ctx["model_id"], "name": ctx["model_id"], "ai_provider": UNKNOWN}
    if behavior is not None and (behavior.countermeasures.mitigations or behavior.countermeasures.response):
        parts = []
        if behavior.countermeasures.mitigations:
            parts.append("ATLAS mitigations: " + ", ".join(
                f"{m} ({catalog.name(m)})" if catalog is not None else m
                for m in behavior.countermeasures.mitigations))
        if behavior.countermeasures.response:
            parts.append("Response: " + ", ".join(s.action for s in behavior.countermeasures.response))
        f["remediation"] = {"desc": ". ".join(parts) + ".",
                            "references": [_atlas_url(m) for m in behavior.countermeasures.mitigations]}
    if response is not None:
        f["response_plan"] = [_response_row(p) for p in response]
    return f


def _response_row(p: Any) -> dict[str, Any]:
    r = p if isinstance(p, dict) else vars(p)
    return {"action_name": r["action"], "params": r.get("params") or {},
            "requires_approval": bool(r["requires_approval"]), "is_reversible": bool(r["reversible"]),
            "blast_radius": r["blast_radius"], "plan_status": r["status"]}


def alert_from_finding(f: Event) -> dict[str, Any]:
    """Rebuild ``Alert.to_dict()`` from a Detection Finding written by ``to_detection_finding``."""
    ev = ((f.get("evidences") or [{}])[0] or {}).get("data") or {}
    sev = {v: k for k, v in SEVERITY_IDS.items()}.get(f.get("severity_id"), "unknown")
    am = f.get("atlas_mapping") or {}
    return {
        "behavior_id": f["finding_info"]["analytic"]["uid"],
        "name": f["finding_info"]["title"],
        "severity": sev,
        "technique": (am.get("technique") or {}).get("uid"),
        "tactics": [t["uid"] for t in am.get("tactics") or []],
        "context": ev.get("context") or {},
        "metrics": ev.get("metrics") or {},
        "evidence": ev.get("matched") or [],
        "window_start": ev.get("window_start"),
    }


# ---------------------------------------------------------------------------- reporting
def mapping_rows(schema: Any = None) -> list[dict[str, Any]]:
    """One row per (source, class, normalized field) with its OCSF path and tier:
    core (OCSF 1.8.0), abm (extension attribute on the path) or unmapped."""
    rows = []
    for name, spec in SOURCES.items():
        for cuid in spec.classes():
            cname = CLASSES[cuid][0]
            for fld, fs in spec.fields_for(cuid).items():
                p = _path(fs)
                tier = "unmapped" if p.startswith("unmapped.") else "core"
                if schema is not None and tier == "core":
                    cur = schema.classes[cname]
                    for part in p.split("."):
                        nm = part[:-3] if part.endswith("[0]") else part
                        a = cur.attributes[nm]
                        if a.source == "abm":
                            tier = "abm"
                            break
                        cur = schema.objects.get(a.object_type or "") if a.type == "object_t" else None
                        if cur is None:
                            break
                rows.append({"source": name, "class_uid": cuid, "class": cname, "field": fld,
                             "path": p + (f" ({fs.true}=true, {fs.false}=false)" if isinstance(fs, Flag) else ""),
                             "tier": tier})
            for alias, canonical in spec.aliases.items():
                rows.append({"source": name, "class_uid": cuid, "class": cname, "field": alias,
                             "path": f"alias of {canonical}", "tier": "alias"})
    return rows


__all__ = [
    "CLASSES", "EXTENSION", "OCSF_VERSION", "SOURCES", "Flag", "OcsfMappingError", "SourceMap",
    "alert_from_finding", "detect_source", "get_path", "load_ocsf_events", "mapping_rows",
    "normalize", "read_ocsf", "set_path", "to_detection_finding", "to_ocsf_event",
]

