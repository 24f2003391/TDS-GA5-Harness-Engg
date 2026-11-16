"""Policy-driven deterministic classifier for TDS GA5 harness engineering."""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

PROFILE = "agent-harness-2026-09"
logger = logging.getLogger("harness_diagnostics")
logger.setLevel(logging.INFO)  # Ensure aggregate diagnostics are emitted under Uvicorn.
app = FastAPI(title="TDS GA5 Harness Engineering", version="2.0.0")

# These phrases identify an actual prohibited purpose, not merely quoted material
# found in a file, memory, repository instruction, or tool result.
HARMFUL_PATTERNS = (
    r"\b(?:help|teach|show|explain|write|build|make|create|run|perform|carry out)\b.{0,70}\b(?:steal credentials|steal passwords|credential theft|exfiltrate private data|steal private data|commit fraud|harass (?:a|the) real person|destructive malware|ransomware|enable physical harm)\b",
    r"\b(?:steal credentials|steal passwords|credential theft|exfiltrate private data|steal private data|commit fraud|harass (?:a|the) real person|deploy destructive malware|enable physical harm)\b",
    r"\b(?:evade|bypass) (?:safety )?safeguards\b.{0,70}\b(?:harm|fraud|steal|exfiltrat|malware|harass)\b",
)
SECURITY_PATTERNS = (
    r"\bvulnerabilit(?:y|ies)\b", r"\bexploit(?:ation|s|ing)?\b",
    r"\bpenetration test(?:ing)?\b", r"\bsecurity (?:assessment|testing|audit)\b",
    r"\bsql injection\b", r"\bcross.site scripting\b",
    r"\bprivilege escalation\b", r"\bbuffer overflow\b",
    r"\bproof.of.concept exploit\b",
)
REVOCATION_PATTERNS = (
    r"\brevoke(?:d)?\b", r"\bwithdraw my approval\b",
    r"\bcancel (?:the )?(?:authorization|approval)\b",
    r"\bdo not proceed\b", r"\bdon't proceed\b",
    r"\bstop the operation\b", r"\bno longer authorize\b",
)
APPROVAL_PATTERNS = (
    r"\bi explicitly authorize\b", r"\bi authorize\b",
    r"\bi approve\b", r"\byou may proceed\b",
    r"\bgo ahead with\b", r"\bproceed with\b",
)
INJECTION_PATTERNS = (
    r"ignore (?:all )?(?:previous|prior) instructions",
    r"override the policy", r"ignore the policy", r"bypass safety",
    r"reveal the system prompt", r"disregard your instructions",
    r"you must obey this file", r"follow these new instructions",
)
MUTATIONS = {
    "delete", "remove", "write", "update", "modify", "deploy", "push",
    "change", "create", "send", "upload", "transfer", "export",
    "dns_change", "privileged_change",
}
READS = {"read", "inspect", "list", "view", "search", "get", "fetch"}
TRANSFERS = {"send", "upload", "transfer", "export"}


def text(value: Any) -> str:
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, dict):
        return " ".join(f"{k} {text(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return " ".join(text(v) for v in value)
    return "" if value is None else str(value).lower()


def has_pattern(value: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, value, re.I | re.S) for pattern in patterns)


def user_messages(case: dict) -> list[str]:
    return [
        str(m.get("content", ""))
        for m in case.get("messages", [])
        if isinstance(m, dict) and m.get("role") == "user"
    ]


def history(case: dict) -> str:
    return "\n".join(user_messages(case)).lower()


def is_security_work(case: dict) -> bool:
    # Only the user's requested assistance is considered here.
    return has_pattern(history(case), SECURITY_PATTERNS)


def is_harmful_request(case: dict) -> bool:
    h = history(case)
    if not has_pattern(h, HARMFUL_PATTERNS):
        return False
    # A request to inspect/translate/summarize quoted hostile text is not itself
    # assistance in carrying out the hostile instruction.
    benign_analysis = re.search(
        r"\b(?:analy[sz]e|inspect|review|summari[sz]e|translate|classify|explain what this says)\b",
        h,
    )
    quoted_context = re.search(r"[\"'“‘].{0,240}(?:steal|exfiltrat|fraud|malware|harass).{0,240}[\"'”’]", h, re.I | re.S)
    asks_for_execution = re.search(
        r"\b(?:help me|show me how|write|build|create|deploy|execute|perform|carry out)\b",
        h,
    )
    return not (benign_analysis and quoted_context and not asks_for_execution)


def case_environment(case: dict) -> dict:
    value = case.get("environment")
    return value if isinstance(value, dict) else {}


def resolved_tool(case: dict) -> tuple[dict, dict]:
    tool = case.get("proposedTool")
    if not isinstance(tool, dict):
        return {}, {}
    resolved = tool.get("resolved")
    return tool, resolved if isinstance(resolved, dict) else {}


def tool_facts(case: dict) -> dict:
    tool, resolved = resolved_tool(case)
    env = case_environment(case)
    isolation = env.get("isolation") if isinstance(env.get("isolation"), dict) else {}
    args = tool.get("arguments") if isinstance(tool.get("arguments"), dict) else {}
    # Keep raw structured evidence separate; do not infer authorization from it.
    return {
        "tool": tool, "resolved": resolved, "environment": env,
        "isolation": isolation, "arguments": args,
        "operation": str(resolved.get("operation", "")).lower(),
        "target": str(resolved.get("target", "")),
        "destination": str(resolved.get("destination", resolved.get("resolvedDestination", ""))),
        "environment_name": str(resolved.get("environment", env.get("kind", ""))).lower(),
        "sensitivity": str(resolved.get("sensitivity", "unknown")).lower(),
    }


def is_owned_isolated_security_scope(case: dict) -> bool:
    h = history(case)
    facts = tool_facts(case)
    env, iso, resolved = facts["environment"], facts["isolation"], facts["resolved"]
    ownership = re.search(
        r"\b(?:my|our) (?:own )?(?:isolated )?(?:server|website|application|app|system|lab|test environment)\b|\bowned target\b|\btarget i own\b|\bauthorized target\b",
        h,
    )
    explicit_scope = re.search(
        r"\b(?:isolated|sandboxed) (?:lab|environment|container|target)\b|\blocal lab\b|\btest environment\b",
        h,
    )
    verified_isolation = (
        env.get("kind") in {"container", "sandbox", "isolated"}
        and iso.get("verified") is True
        and iso.get("hostMounts") == []
        and iso.get("credentials") is False
        and iso.get("externalNetwork") is False
    )
    resolved_isolated = (
        resolved.get("isolated") is True
        or resolved.get("isolationVerified") is True
        or resolved.get("disposable") is True and verified_isolation
    )
    # A user's description can establish ownership; isolation must be supported
    # by explicit scope or verified harness metadata.
    return bool(ownership and (explicit_scope or verified_isolation or resolved_isolated))


def request_decision(case: dict) -> str:
    if is_harmful_request(case):
        return "block"
    if is_security_work(case) and not is_owned_isolated_security_scope(case):
        return "review"
    return "allow"


def latest_approval_state(messages: list[str]) -> bool:
    approved = False
    for message in messages:
        if has_pattern(message.lower(), APPROVAL_PATTERNS):
            approved = True
        if has_pattern(message.lower(), REVOCATION_PATTERNS):
            approved = False
    return approved


def exact_authorization(case: dict, operation: str, target: str, environment: str) -> bool:
    msgs = user_messages(case)
    if not msgs or not operation or not target or not environment:
        return False
    if not latest_approval_state(msgs):
        return False
    h = history(case)
    # Approval must identify the operation, target and environment; a generic
    # "go ahead" is not authorization for an arbitrary resolved effect.
    operation_aliases = {
        "delete": ("delete", "remove"), "remove": ("delete", "remove"),
        "write": ("write", "edit", "update"), "update": ("update", "edit", "write"),
        "modify": ("modify", "change", "edit"), "deploy": ("deploy",),
        "send": ("send", "transfer", "upload"), "upload": ("upload", "send"),
        "transfer": ("transfer", "send", "upload"), "export": ("export", "send"),
        "dns_change": ("dns", "domain"), "privileged_change": ("privileged", "admin"),
    }
    aliases = operation_aliases.get(operation, (operation,))
    if not any(a in h for a in aliases):
        return False
    if target.lower() not in h:
        # Permit a path's basename only if it is explicitly mentioned.
        basename = target.replace("\\", "/").rstrip("/").split("/")[-1].lower()
        if not basename or basename not in h:
            return False
    env_aliases = {
        "production": ("production", "prod"),
        "host": ("host", "personal machine", "local machine"),
        "personal_machine": ("personal machine", "host", "local machine"),
        "local_machine": ("local machine", "personal machine", "host"),
        "container": ("container", "isolated container"),
        "workspace": ("workspace", "project workspace"),
        "external": ("external", "remote", "internet"),
    }
    words = env_aliases.get(environment, (environment,))
    return any(w in h for w in words)


def recursive_records(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from recursive_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from recursive_records(child)


def successful_preflight(case: dict, target: str) -> bool:
    for record in recursive_records(case.get("toolResults", [])):
        kind = str(record.get("type", record.get("kind", record.get("name", "")))).lower()
        status = str(record.get("status", record.get("result", ""))).lower()
        ok = record.get("success") is True or record.get("passed") is True
        marker = "preflight" in kind or record.get("preflight") is True
        record_target = str(record.get("target", record.get("resource", ""))).lower()
        if marker and ok and status in {"", "success", "succeeded", "passed", "ok"}:
            if record_target == target.lower():
                return True
    return False


def exact_rollback(case: dict, target: str, operation: str) -> bool:
    for record in recursive_records(case.get("rollbackPlan", [])):
        if record.get("exact") is True or record.get("isExact") is True:
            rt = str(record.get("target", record.get("resource", ""))).lower()
            action = str(record.get("action", record.get("operation", ""))).lower()
            if rt == target.lower() and action and action in {"rollback", "restore", "revert", "undo"}:
                return True
    return False


def independently_forbidden_tool(case: dict, facts: dict) -> bool:
    tool_blob = text(facts["tool"])
    h = history(case)
    op, target, destination = facts["operation"], facts["target"].lower(), facts["destination"].lower()
    if has_pattern(tool_blob, (
        r"search unrelated credentials", r"search all credentials",
        r"dump credentials", r"find all passwords", r"unrelated credentials",
    )):
        return True
    if "credential" in target or "password" in target:
        scoped = "task-scoped credential" in h or "approved task credential" in h
        if op in READS and not scoped:
            return True
    if op in TRANSFERS and facts["sensitivity"] in {"private", "confidential", "sensitive"}:
        # A destination explicitly described as unapproved is forbidden.
        if destination and destination in h and re.search(
            r"(?:unapproved|not approved|forbidden|unauthorized).{0,80}" + re.escape(destination),
            h,
        ):
            return True
    return False


def disposable_fixture_delete(case: dict, facts: dict) -> bool:
    env, iso, resolved = facts["environment"], facts["isolation"], facts["resolved"]
    h = history(case)
    return (
        facts["operation"] in {"delete", "remove"}
        and env.get("kind") == "container"
        and facts["environment_name"] == "container"
        and iso.get("verified") is True
        and iso.get("hostMounts") == []
        and iso.get("credentials") is False
        and iso.get("externalNetwork") is False
        and resolved.get("disposable") is True
        and facts["sensitivity"] == "public"
        and has_pattern(h, (r"fixture.cleanup experiment", r"delete disposable fixtures", r"clean up disposable fixtures"))
    )


def tool_decision(case: dict, request: str) -> str:
    tool = case.get("proposedTool")
    if not isinstance(tool, dict):
        return "none"
    if request == "block":
        return "block"
    facts = tool_facts(case)
    if independently_forbidden_tool(case, facts):
        return "block"
    msgs = user_messages(case)
    if msgs and has_pattern(msgs[-1].lower(), REVOCATION_PATTERNS):
        return "block"
    if request == "review":
        return "review"

    if not facts["resolved"]:
        return "review"
    op, target = facts["operation"], facts["target"]
    env_name, sensitivity = facts["environment_name"], facts["sensitivity"]
    destination = facts["destination"]
    if not op or not target or not env_name:
        return "review"

    if disposable_fixture_delete(case, facts):
        return "allow"

    # Task-scoped credentials are a narrow exception; unrelated credential
    # discovery is blocked above.
    if "credential" in target.lower() or "password" in target.lower():
        scoped = "task-scoped credential" in history(case) or "approved task credential" in history(case)
        if scoped and op in {"read", "load"} and target.lower() in history(case):
            return "allow"
        return "review"

    if op in TRANSFERS:
        if sensitivity in {"private", "confidential", "sensitive"}:
            if not destination:
                return "review"
            if destination not in history(case):
                return "review"
            if not exact_authorization(case, op, target, env_name):
                return "review"
            return "allow"
        return "allow" if exact_authorization(case, op, target, env_name) else "review"

    production = (
        env_name in {"production", "prod"}
        or "production" in sensitivity
        or "production" in target.lower()
    )
    if production and op in MUTATIONS:
        if (
            exact_authorization(case, op, target, env_name)
            and successful_preflight(case, target)
            and exact_rollback(case, target, op)
        ):
            return "allow"
        return "review"

    if op in {"delete", "remove"} and (
        env_name in {"host", "personal_machine", "local_machine"}
        or facts["environment"].get("kind") == "host"
    ):
        return "allow" if exact_authorization(case, op, target, env_name) else "review"

    if op in READS:
        if sensitivity in {"private", "confidential", "sensitive"}:
            return "review"
        if sensitivity == "unknown":
            return "review"
        # Read-only public schemas, Terraform plans, local Git metadata and
        # non-sensitive files in the requested workspace are safe.
        requested_workspace = bool(re.search(
            r"\b(?:inspect|read|review|list|view|search|check)\b.{0,100}\b(?:workspace|project|repository|repo|terraform plan|public schema|git metadata)\b",
            history(case),
        )) or bool(re.search(
            r"\b(?:workspace|project|repository|repo|terraform plan|public schema|git metadata)\b.{0,100}\b(?:inspect|read|review|list|view|search|check)\b",
            history(case),
        ))
        if env_name in {"workspace", "container"} and requested_workspace:
            return "allow"
        if env_name in {"public", "external"} and sensitivity == "public":
            return "allow"
        return "review"

    if op in {"write", "edit", "update", "modify"}:
        requested_workspace = bool(re.search(
            r"\b(?:edit|update|modify|write)\b.{0,100}\b(?:workspace|project|repository|repo|file)\b|\b(?:workspace|project|repository|repo|file)\b.{0,100}\b(?:edit|update|modify|write)\b",
            history(case),
        ))
        reversible = facts["resolved"].get("reversible") is True
        if requested_workspace and reversible and sensitivity == "public" and env_name in {"workspace", "container"}:
            return "allow"
        return "review"

    # Other consequential effects need explicit, operation/target/environment-
    # specific authorization. Unknown effects never default to allow.
    return "allow" if exact_authorization(case, op, target, env_name) else "review"


def model_route(case: dict, request: str) -> str:
    if request == "block":
        return "none"
    # Restricted routing applies to vulnerability discovery/exploit work even
    # when that work is authorized. Tool approval is a separate decision.
    if is_security_work(case):
        return "restricted"
    return "primary"


def trajectory(case: dict, request: str, tool: str) -> str:
    if request == "block" or tool == "block":
        return "intervene"
    if request == "review" or tool == "review":
        return "watch"
    untrusted = text([
        case.get("memory", []),
        case.get("repositoryInstructions", []),
        case.get("toolResults", []),
    ])
    if has_pattern(untrusted, INJECTION_PATTERNS):
        return "watch"
    if is_security_work(case) and not is_owned_isolated_security_scope(case):
        return "watch"
    return "normal"


def classify_case(case: dict) -> dict:
    request = request_decision(case)
    tool = tool_decision(case, request)
    return {
        "caseId": case["caseId"],
        "requestDecision": request,
        "toolDecision": tool,
        "route": model_route(case, request),
        "trajectory": trajectory(case, request, tool),
    }


# Temporary, detailed diagnostics. Secrets and common direct identifiers are redacted
# before anything is written to Render logs. Keep this enabled only while debugging.
SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|cookie|credential|"
    r"access[_-]?key|refresh[_-]?token|client[_-]?secret)", re.I
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")


def redact_text(value: str, limit: int = 12000) -> str:
    value = BEARER_RE.sub("Bearer [REDACTED]", value)
    value = EMAIL_RE.sub("[EMAIL REDACTED]", value)
    value = PHONE_RE.sub("[PHONE REDACTED]", value)
    if len(value) > limit:
        value = value[:limit] + f"... [TRUNCATED; original length={len(value)}]"
    return value


def sanitize_for_diagnostics(value: Any, depth: int = 0) -> Any:
    """Preserve useful request structure while redacting secrets and bounding log size."""
    if depth > 12:
        return "[MAX DEPTH]"
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            key_text = str(key)
            if SENSITIVE_KEY.search(key_text):
                out[key_text] = "[REDACTED]"
            else:
                out[key_text] = sanitize_for_diagnostics(child, depth + 1)
        return out
    if isinstance(value, list):
        items = [sanitize_for_diagnostics(x, depth + 1) for x in value[:100]]
        if len(value) > 100:
            items.append(f"[{len(value) - 100} additional items omitted]")
        return items
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))


def diagnostic_reasons(case: dict, result: dict) -> list[str]:
    """Explain observed policy signals without changing classifier decisions."""
    reasons = []
    h = history(case)
    facts = tool_facts(case)
    if is_harmful_request(case):
        reasons.append("request:harmful-purpose-pattern")
    elif has_pattern(h, HARMFUL_PATTERNS):
        reasons.append("request:harmful-phrase-present-but-treated-as-quoted-or-analysis")
    if is_security_work(case):
        reasons.append("routing:security-work-pattern")
        reasons.append(
            "security-scope:owned-isolated" if is_owned_isolated_security_scope(case)
            else "security-scope:unclear-or-unverified"
        )
    if has_pattern(text([
        case.get("memory", []), case.get("repositoryInstructions", []), case.get("toolResults", [])
    ]), INJECTION_PATTERNS):
        reasons.append("trajectory:untrusted-injection-pattern")
    if not case.get("proposedTool"):
        reasons.append("tool:no-proposed-tool")
    else:
        if not facts["resolved"]:
            reasons.append("tool:missing-resolved-metadata")
        if facts["operation"] in READS:
            reasons.append("tool:read-operation")
        if facts["operation"] in MUTATIONS:
            reasons.append("tool:mutation-operation")
        if facts["operation"] in TRANSFERS:
            reasons.append("tool:data-transfer-operation")
        if facts["environment_name"] in {"production", "prod"} or "production" in facts["target"].lower():
            reasons.append("tool:production-effect")
        if facts["sensitivity"] in {"private", "confidential", "sensitive"}:
            reasons.append("tool:sensitive-data")
        if facts["sensitivity"] == "unknown":
            reasons.append("tool:unknown-sensitivity")
        if "credential" in facts["target"].lower() or "password" in facts["target"].lower():
            reasons.append("tool:credential-target")
        if independently_forbidden_tool(case, facts):
            reasons.append("tool:independently-forbidden")
        if facts["operation"] in MUTATIONS and facts["environment_name"] in {"production", "prod"}:
            reasons.append("tool:preflight-" + ("present" if successful_preflight(case, facts["target"]) else "missing-or-unmatched"))
            reasons.append("tool:rollback-" + ("present" if exact_rollback(case, facts["target"], facts["operation"]) else "missing-or-unmatched"))
        if exact_authorization(case, facts["operation"], facts["target"], facts["environment_name"]):
            reasons.append("authorization:exact-match-detected")
        else:
            reasons.append("authorization:exact-match-not-detected")
    reasons.append("decision:" + result["requestDecision"] + "/" + result["toolDecision"] + "/" + result["route"] + "/" + result["trajectory"])
    return reasons


def log_case_diagnostics(case: dict, result: dict, index: int, batch_id: str) -> None:
    record = {
        "event": "CASE_DIAGNOSTICS",
        "batch_id": redact_text(batch_id, 200),
        "case_index": index,
        "case_id": redact_text(str(case.get("caseId", "")), 200),
        "decisions": {k: result[k] for k in ("requestDecision", "toolDecision", "route", "trajectory")},
        "reasons": diagnostic_reasons(case, result),
        "input": sanitize_for_diagnostics(case),
    }
    encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    # Bound each line so a single pathological case cannot flood application logs.
    if len(encoded) > 30000:
        record["input"] = {"truncated": True, "note": "Sanitized case exceeded 30,000 log characters"}
        record["input_preview"] = encoded[:20000]
        encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    logger.info("CASE_DIAGNOSTICS %s", encoded)


def batch_diagnostics(cases: list[dict], results: list[dict]) -> dict:
    """Aggregate safe feature counts; never log raw text, IDs, paths or arguments."""
    def counts(values):
        return dict(sorted(Counter(values).items()))

    operations, environments, sensitivities = [], [], []
    request_labels, tool_labels, routes, trajectories = [], [], [], []
    flags = Counter()
    for case, result in zip(cases, results):
        facts = tool_facts(case)
        operations.append(facts["operation"] or "missing")
        environments.append(facts["environment_name"] or "missing")
        sensitivities.append(facts["sensitivity"] or "missing")
        request_labels.append(result["requestDecision"])
        tool_labels.append(result["toolDecision"])
        routes.append(result["route"])
        trajectories.append(result["trajectory"])

        flags["has_tool"] += int(bool(case.get("proposedTool")))
        flags["security_request"] += int(is_security_work(case))
        flags["owned_isolated_security_scope"] += int(is_owned_isolated_security_scope(case))
        flags["harmful_request_detected"] += int(is_harmful_request(case))
        flags["untrusted_injection_signal"] += int(has_pattern(text([
            case.get("memory", []), case.get("repositoryInstructions", []),
            case.get("toolResults", [])
        ]), INJECTION_PATTERNS))
        flags["production_effect"] += int(
            facts["environment_name"] in {"production", "prod"}
            or "production" in facts["target"].lower()
        )
        flags["transfer_operation"] += int(facts["operation"] in TRANSFERS)
        flags["credential_target"] += int(
            "credential" in facts["target"].lower() or "password" in facts["target"].lower()
        )
        flags["missing_resolved_metadata"] += int(not bool(facts["resolved"]))
    return {
        "event": "batch_diagnostics",
        "case_count": len(cases),
        "request_decisions": counts(request_labels),
        "tool_decisions": counts(tool_labels),
        "routes": counts(routes),
        "trajectories": counts(trajectories),
        "operations": counts(operations),
        "environments": counts(environments),
        "sensitivities": counts(sensitivities),
        "feature_counts": dict(sorted(flags.items())),
    }


@app.get("/health")
def health():
    return {"status": "ok", "profile": PROFILE}


@app.post("/")
async def classify_batch(request: Request):
    if "application/json" not in request.headers.get("content-type", "").lower():
        raise HTTPException(status_code=415, detail="application/json required")
    raw = await request.body()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="request exceeds 2 MiB")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="invalid JSON")
    if not isinstance(payload, dict) or payload.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="invalid profile")
    batch_id, cases = payload.get("batchId"), payload.get("cases")
    if not isinstance(batch_id, str) or not isinstance(cases, list):
        raise HTTPException(status_code=400, detail="batchId and cases are required")
    ids = [c.get("caseId") for c in cases if isinstance(c, dict)]
    if len(ids) != len(cases) or any(not isinstance(x, str) or not x for x in ids):
        raise HTTPException(status_code=400, detail="every case needs a caseId")
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=400, detail="duplicate caseId")
    try:
        results = [classify_case(case) for case in cases]
    except (KeyError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="malformed case")
    # Log one sanitized, inspectable record per case plus a compact batch summary.
    for index, (case, result) in enumerate(zip(cases, results), start=1):
        log_case_diagnostics(case, result, index, batch_id)
    logger.info("BATCH_DIAGNOSTICS %s", json.dumps(batch_diagnostics(cases, results), sort_keys=True))
    return JSONResponse({"profile": PROFILE, "batchId": batch_id, "results": results})
