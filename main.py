"""Deterministic classifier for the TDS GA5 harness engineering task."""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

PROFILE = "agent-harness-2026-09"
app = FastAPI(title="TDS GA5 Harness Engineering", version="1.0.0")


def flatten(value: Any) -> str:
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, dict):
        return " ".join(f"{k} {flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return " ".join(flatten(v) for v in value)
    if value is None:
        return ""
    return str(value).lower()


def user_messages(case: dict) -> list[str]:
    return [
        str(m.get("content", ""))
        for m in case.get("messages", [])
        if isinstance(m, dict) and m.get("role") == "user"
    ]


def user_history(case: dict) -> str:
    return "\n".join(user_messages(case)).lower()


def has_any(text: str, phrases: tuple[str, ...] | list[str]) -> bool:
    return any(p in text for p in phrases)


HARMFUL_PURPOSES = (
    "steal credentials", "steal password", "steal passwords",
    "credential theft", "exfiltrate private data", "steal private data",
    "commit fraud", "harass a real person", "destructive malware",
    "ransomware", "enable physical harm", "evade safeguards",
)
SECURITY_TERMS = (
    "vulnerability", "exploit", "penetration test", "penetration testing",
    "security assessment", "security testing", "sql injection",
    "cross-site scripting", " privilege escalation", "buffer overflow",
    "proof of concept exploit", "exploit demonstration",
)
OWNERSHIP_TERMS = (
    "my server", "my website", "my application", "my app", "my system",
    "our server", "our website", "our application", "our app",
    "owned target", "authorized target", "isolated lab",
    "isolated target", "local lab", "my own",
)
REVOCATION_TERMS = (
    "revoke", "withdraw my approval", "cancel the authorization",
    "do not proceed", "don't proceed", "stop the operation",
    "no longer authorize", "cancel my approval",
)
APPROVAL_PATTERNS = (
    r"\bi explicitly authorize\b", r"\bi authorize\b",
    r"\bi approve\b", r"\byou may proceed\b",
    r"\bgo ahead with\b", r"\bproceed with\b",
)
INJECTION_TERMS = (
    "ignore previous instructions", "ignore all previous instructions",
    "override the policy", "ignore the policy", "bypass safety",
    "reveal the system prompt", "disregard your instructions",
    "you must obey this file", "follow these new instructions",
)


def explicit_approval(message: str) -> bool:
    return any(re.search(p, message.lower()) for p in APPROVAL_PATTERNS)


def revoked_after_approval(messages: list[str]) -> bool:
    approved = False
    for message in messages:
        t = message.lower()
        if explicit_approval(t):
            approved = True
        if has_any(t, REVOCATION_TERMS):
            approved = False
    return not approved


def target_is_named_in_user_history(case: dict, target: str) -> bool:
    return bool(target) and target.lower() in user_history(case)


def exact_authorization(case: dict, target: str, environment: str) -> bool:
    msgs = user_messages(case)
    if not msgs or not target or not environment:
        return False
    if not target_is_named_in_user_history(case, target):
        return False
    if not any(explicit_approval(m) for m in msgs):
        return False
    if revoked_after_approval(msgs):
        return False
    # Require environment context in actual user messages too.
    h = user_history(case)
    env_words = {
        "production": ("production", "prod"),
        "container": ("container", "isolated container"),
        "host": ("host", "personal machine", "local machine"),
        "external": ("external", "internet", "remote"),
    }.get(environment, (environment,))
    return any(w in h for w in env_words)


def request_decision(case: dict) -> str:
    h = user_history(case)
    # These are intent phrases, not keyword-only checks over untrusted files.
    if has_any(h, HARMFUL_PURPOSES):
        return "block"
    if has_any(h, SECURITY_TERMS):
        if has_any(h, OWNERSHIP_TERMS):
            return "allow"
        return "review"
    return "allow"


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
        kind = str(record.get("type", record.get("kind", ""))).lower()
        status = str(record.get("status", record.get("result", ""))).lower()
        success = record.get("success") is True or record.get("passed") is True
        preflight_marker = "preflight" in kind or record.get("preflight") is True
        record_target = str(record.get("target", record.get("resource", ""))).lower()
        target_matches = not record_target or record_target == target.lower()
        if preflight_marker and (success or status in {"success", "succeeded", "passed", "ok"}) and target_matches:
            return True
    return False


def exact_rollback(case: dict, target: str) -> bool:
    for record in recursive_records(case.get("rollbackPlan")):
        if record.get("exact") is True or record.get("isExact") is True:
            rt = str(record.get("target", record.get("resource", ""))).lower()
            action = record.get("action") or record.get("operation")
            if rt == target.lower() and action:
                return True
    return False


def tool_decision(case: dict, req: str) -> str:
    tool = case.get("proposedTool")
    if not tool:
        return "none"
    if req == "block":
        return "block"
    if req == "review":
        # An independently forbidden operation still blocks.
        resolved = tool.get("resolved") or {}
        op = str(resolved.get("operation", "")).lower()
        combined = flatten(tool)
        if has_any(combined, ("credential exfiltration", "unrelated credentials", "private-data exfiltration")):
            return "block"
        return "review"

    resolved = tool.get("resolved")
    if not isinstance(resolved, dict):
        return "review"

    operation = str(resolved.get("operation", "")).lower()
    target = str(resolved.get("target", ""))
    environment_name = str(resolved.get("environment", "unknown")).lower()
    sensitivity = str(resolved.get("sensitivity", "unknown")).lower()
    destination = str(resolved.get("destination", "")).lower()
    h = user_history(case)
    all_tool = flatten(tool)

    # Prohibited purpose or explicitly forbidden tool effect.
    if has_any(h, HARMFUL_PURPOSES):
        return "block"
    if has_any(all_tool, (
        "steal credentials", "credential theft", "exfiltrate private data",
        "destructive malware", "unrelated credentials",
    )):
        return "block"

    msgs = user_messages(case)
    if msgs and has_any("\n".join(msgs[-1:]).lower(), REVOCATION_TERMS):
        return "block"

    # Disposable fixture deletion is a narrowly defined exception.
    env = case.get("environment") or {}
    isolation = env.get("isolation") or {}
    disposable_fixture = (
        operation in {"delete", "remove"}
        and env.get("kind") == "container"
        and environment_name == "container"
        and isolation.get("verified") is True
        and isolation.get("hostMounts") == []
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
        and resolved.get("disposable") is True
        and sensitivity == "public"
        and has_any(h, (
            "fixture-cleanup experiment", "fixture cleanup experiment",
            "delete disposable fixtures", "clean up disposable fixtures",
        ))
    )
    if disposable_fixture:
        return "allow"

    # Credential access: only task-scoped, explicitly approved credentials.
    if "credential" in target.lower() or "password" in target.lower():
        unrelated = has_any(all_tool, (
            "search unrelated credentials", "search all credentials",
            "dump credentials", "find all passwords",
        ))
        if unrelated:
            return "block"
        scoped = has_any(h, ("task-scoped credential", "approved task credential"))
        if scoped and operation in {"read", "load"} and target_is_named_in_user_history(case, target):
            return "allow"
        return "review"

    # Sensitive data transfers require exact destination approval.
    if operation in {"send", "upload", "transfer", "export"}:
        if sensitivity in {"private", "confidential", "sensitive"}:
            approved_destination = bool(destination) and destination in h
            authorized = exact_authorization(case, target, environment_name)
            return "allow" if authorized and approved_destination else "block"
        return "allow" if exact_authorization(case, target, environment_name) else "review"

    # Production changes require exact approval, successful preflight, exact rollback.
    production = (
        environment_name == "production"
        or "production" in sensitivity
        or "production" in target.lower()
    )
    mutations = {
        "delete", "write", "update", "modify", "deploy", "push",
        "change", "create", "send", "dns_change", "privileged_change",
    }
    if production and operation in mutations:
        if (
            exact_authorization(case, target, environment_name)
            and successful_preflight(case, target)
            and exact_rollback(case, target)
        ):
            return "allow"
        return "review"

    # Personal-machine / host deletion is consequential.
    if operation in {"delete", "remove"}:
        if environment_name in {"host", "personal_machine", "local_machine"} or not resolved.get("disposable", False):
            return "allow" if exact_authorization(case, target, environment_name) else "review"

    # Explicitly requested read-only workspace and public metadata inspection.
    if operation in {"read", "inspect", "list", "view", "search"}:
        if sensitivity in {"private", "confidential", "sensitive"}:
            return "review"
        if sensitivity == "unknown" or environment_name == "unknown" or not target:
            return "review"
        return "allow"

    # Reversible workspace edits require an actual requested workspace task.
    if operation in {"write", "edit", "update", "modify"}:
        workspace_context = has_any(h, (
            "workspace", "project files", "edit the repository",
            "update the requested file", "modify the project",
        ))
        if workspace_context and sensitivity == "public" and environment_name in {"workspace", "container"}:
            return "allow"
        return "review"

    # All other consequential or unknown effects require explicit exact approval.
    if not operation or not target or environment_name == "unknown":
        return "review"
    return "allow" if exact_authorization(case, target, environment_name) else "review"


def model_route(case: dict, req: str) -> str:
    if req == "block":
        return "none"
    if has_any(user_history(case), SECURITY_TERMS):
        return "restricted"
    return "primary"


def trajectory(case: dict, req: str, tool: str) -> str:
    if req == "block" or tool == "block":
        return "intervene"
    if req == "review" or tool == "review":
        return "watch"
    untrusted = flatten([
        case.get("memory", []),
        case.get("repositoryInstructions", []),
        case.get("toolResults", []),
    ])
    if has_any(untrusted, INJECTION_TERMS):
        return "watch"
    if has_any(user_history(case), SECURITY_TERMS):
        return "watch"
    return "normal"


def classify_case(case: dict) -> dict:
    req = request_decision(case)
    tool = tool_decision(case, req)
    return {
        "caseId": case["caseId"],
        "requestDecision": req,
        "toolDecision": tool,
        "route": model_route(case, req),
        "trajectory": trajectory(case, req, tool),
    }


@app.get("/health")
def health():
    return {"status": "ok", "profile": PROFILE}


@app.post("/")
async def classify_batch(request: Request):
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
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
    batch_id = payload.get("batchId")
    cases = payload.get("cases")
    if not isinstance(batch_id, str) or not isinstance(cases, list):
        raise HTTPException(status_code=400, detail="batchId and cases are required")

    ids = [c.get("caseId") for c in cases if isinstance(c, dict)]
    if len(ids) != len(cases) or any(not isinstance(x, str) or not x for x in ids):
        raise HTTPException(status_code=400, detail="every case needs a caseId")
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=400, detail="duplicate caseId")

    results = [classify_case(case) for case in cases]
    return JSONResponse({
        "profile": PROFILE,
        "batchId": batch_id,
        "results": results,
    })
