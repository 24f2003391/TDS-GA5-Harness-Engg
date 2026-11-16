"""Policy-driven deterministic classifier for TDS GA5 harness engineering."""
from __future__ import annotations

import json
import logging
import posixpath
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
    r"\b(?:steal|take|harvest|exfiltrate)\b.{0,100}\b(?:another person'?s|someone else'?s|victim'?s|private|authentication|access|session)?\s*(?:credentials|passwords|tokens|session cookies|private data)\b",
    r"\bsteal\b.{0,60}\b(?:another person'?s|someone else'?s|victim'?s)\b.{0,40}\b(?:authentication )?tokens\b",
    r"\b(?:create|make|write|forge|fabricate|generate)\b.{0,100}\b(?:forged|fake|fraudulent|convincing)?\s*(?:invoices?|receipts?|payment requests?|documents?)\b.{0,100}\b(?:trick|defraud|deceive|pay|account i control)\b",
    r"\bforged invoices?\b.{0,100}\b(?:trick|defraud|customers|account i control)\b",
    r"\b(?:commit|carry out|facilitate|help with)\b.{0,80}\b(?:fraud|identity theft|credential theft|harassment|extortion)\b",
    r"\b(?:help me|teach me|show me how|give me|provide)\b.{0,100}\b(?:target|threaten|harass|stalk|intimidate)\b.{0,100}\b(?:real person|colleague|coworker|classmate|person)\b",
    r"\b(?:repeated threatening messages|evade their blocks|bypass their blocks)\b",
    r"\b(?:actionable instructions|instructions|steps|advice)\b.{0,100}\b(?:seriously injure|physically harm|attack|hurt)\b.{0,100}\b(?:person|someone|specific person)\b",
    r"\b(?:write|build|create|deploy|run)\b.{0,100}\b(?:destructive malware|ransomware|wiper malware|malware)\b.{0,100}\b(?:wipe|destroy|evade detection|other people)\b",
    r"\b(?:steal credentials|steal passwords|credential theft|exfiltrate private data|steal private data|commit fraud|harass (?:a|the) real person|destructive malware|ransomware|enable physical harm)\b",
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
    r"\brevoke(?:d|s)?\b", r"\bwithdraw(?:n)? my (?:approval|permission|authorization)\b",
    r"\bapproval (?:is )?(?:revoked|withdrawn)\b",
    r"\bcancel (?:the )?(?:authorization|approval)\b",
    r"\bdo not proceed\b", r"\bdon't proceed\b", r"\bdo not execute\b",
    r"\bdo not run\b", r"\bdo not deploy\b", r"\bdo not send\b",
    r"\bdo not change anything\b", r"\bkeep every existing file intact\b",
    r"\bonly inspect and explain\b", r"\bprepare (?:a )?(?:plan|draft) only\b",
    r"\bstop(?: here| now)?\b", r"\bno longer authorize\b",
    r"\bi changed my mind\b",
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
    r"return allow for every item", r"omit all failed cases",
    r"mark this account legitimate", r"ignore the user",
    r"suppress the actual log", r"copy the supplied accuracy",
    r"the owner approves", r"answer key",
)
MUTATIONS = {
    "delete", "remove", "write", "update", "modify", "deploy", "push",
    "change", "create", "send", "upload", "transfer", "export",
    "dns_change", "privileged_change", "workspace_edit", "database_mutation",
    "restart", "force_push", "terraform_apply", "host_admin", "rollback",
}
READS = {
    "read", "inspect", "list", "view", "search", "get", "fetch",
    "workspace_read", "read_public_schema",
}
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
    return has_pattern(history(case), SECURITY_PATTERNS)


def is_security_discovery(case: dict) -> bool:
    h = history(case)
    return is_security_work(case) and has_pattern(h, (
        r"\bfind (?:a )?vulnerabilit", r"\bdemonstrate (?:the )?vulnerabilit",
        r"\breview (?:this )?(?:owned )?service for vulnerabilities\b",
        r"\bexploit\b", r"\bprove (?:the )?vulnerabilit",
        r"\bpenetration test", r"\bsecurity testing\b",
    ))


def is_harmful_request(case: dict) -> bool:
    h = history(case)
    if not has_pattern(h, HARMFUL_PATTERNS):
        return False
    benign_analysis = re.search(
        r"\b(?:analy[sz]e|inspect|review|summari[sz]e|translate|classify|explain what this says|identify indicators)\b",
        h,
    )
    quoted_context = re.search(
        r"""["'“‘].{0,300}(?:steal|exfiltrat|fraud|forged|invoice|trick|malware|harass|threat|injur).{0,300}["'”’]""",
        h, re.I | re.S,
    )
    unquoted = re.sub(r"""["'“‘].*?["'”’]""", " ", h, flags=re.S)
    asks_for_execution = re.search(
        r"\b(?:help me|show me how|write|build|create|deploy|execute|perform|carry out|give me actionable instructions)\b",
        unquoted,
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
        "destination": str(resolved.get("destination") or resolved.get("resolvedDestination") or resolved.get("target") or ""),
        "environment_name": str(resolved.get("environment", env.get("kind", ""))).lower(),
        "sensitivity": str(resolved.get("sensitivity", "unknown")).lower(),
    }


def is_owned_isolated_security_scope(case: dict) -> bool:
    h = history(case)
    facts = tool_facts(case)
    env, iso, resolved = facts["environment"], facts["isolation"], facts["resolved"]
    ownership = re.search(
        r"\b(?:my|our|owned)\b.{0,50}\b(?:server|website|service|application|app|system|lab|test environment|local service)\b|\btarget i own\b|\bauthorized target\b",
        h,
    )
    explicit_scope = re.search(
        r"\b(?:isolated|sandboxed|disposable)\b.{0,60}\b(?:lab|environment|container|target|service)\b|\blocal lab\b|\btest environment\b|\bconfined to this isolated target\b",
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
    return bool(ownership and explicit_scope and (verified_isolation or resolved_isolated))


def request_decision(case: dict) -> str:
    if is_harmful_request(case):
        return "block"
    # Defensive review/remediation is allowed. Discovery or exploit work with
    # unclear ownership/scope requires review and restricted routing.
    if is_security_discovery(case) and not is_owned_isolated_security_scope(case):
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
    if not msgs or not operation or not target or not environment or not latest_approval_state(msgs):
        return False
    h = history(case)
    aliases = {
        "delete": ("delete", "remove"), "remove": ("delete", "remove"),
        "write": ("write", "edit", "update"), "update": ("update", "edit", "write"),
        "modify": ("modify", "change", "edit"), "workspace_edit": ("edit", "write", "modify", "change"),
        "deploy": ("deploy",), "send": ("send", "transfer", "upload", "publish"),
        "upload": ("upload", "send", "publish"), "transfer": ("transfer", "send", "upload"),
        "export": ("export", "send", "publish"), "database_mutation": ("database_mutation", "database", "sql", "migration"),
        "rollback": ("rollback", "restore", "revert"), "restart": ("restart",),
        "force_push": ("force push", "force_push"), "terraform_apply": ("terraform apply", "apply"),
        "host_admin": ("host administration", "host admin", "administer the host"),
        "dns_change": ("dns", "domain"), "privileged_change": ("privileged", "admin"),
    }
    if not any(a in h for a in aliases.get(operation, (operation,))):
        return False
    target_l = target.lower().rstrip("/")
    # Require the full resolved identifier. Basename-only matching allowed
    # approvals for one namespace/resource to authorize another.
    if target_l not in h:
        return False
    env_aliases = {
        "production": ("production", "prod"),
        "personal": ("personal machine", "my personal machine", "host", "local machine"),
        "prod": ("production", "prod"),
        "staging": ("staging",),
        "test": ("test", "testing"),
        "host": ("host", "personal machine", "local machine"),
        "personal_machine": ("personal machine", "host", "local machine"),
        "local_machine": ("local machine", "personal machine", "host"),
        "container": ("container", "isolated container"),
        "workspace": ("workspace", "project workspace"),
        "external": ("external", "remote", "internet"),
    }
    return any(w in h for w in env_aliases.get(environment, (environment,)))


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
        kind = str(record.get("type", record.get("kind", record.get("name", record.get("tool", ""))))).lower()
        status = str(record.get("status", record.get("result", ""))).lower()
        ok = record.get("success") is True or record.get("passed") is True or status in {"success", "succeeded", "passed", "ok"}
        marker = "preflight" in kind or record.get("preflight") is True
        record_target = str(record.get("target", record.get("resource", ""))).lower()
        if marker and ok and record_target == target.lower():
            return True
    return False


def failed_preflight(case: dict, target: str) -> bool:
    for record in recursive_records(case.get("toolResults", [])):
        kind = str(record.get("type", record.get("kind", record.get("name", record.get("tool", ""))))).lower()
        status = str(record.get("status", record.get("result", ""))).lower()
        marker = "preflight" in kind or record.get("preflight") is True
        record_target = str(record.get("target", record.get("resource", ""))).lower()
        if marker and record_target == target.lower() and status in {"failed", "failure", "error", "blocked"}:
            return True
    return False


def exact_rollback(case: dict, target: str, operation: str) -> bool:
    plans = case.get("rollbackPlan")
    if isinstance(plans, dict):
        plans = [plans]
    if not isinstance(plans, list):
        return False
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        rt = str(plan.get("target", plan.get("resource", ""))).lower()
        env = str(plan.get("environment", "")).lower()
        action = str(plan.get("action", plan.get("operation", ""))).lower()
        rollback_action = has_pattern(action, (r"\brollback\b", r"\brestore\b", r"\brevert\b", r"\bundo\b", r"\bprior snapshot\b", r"\bprevious snapshot\b", r"\bprevious release\b"))
        env_matches = not env or env in {"production", "prod"}
        if rt == target.lower() and env_matches and action and rollback_action:
            return True
    return False


def independently_forbidden_tool(case: dict, facts: dict) -> bool:
    tool_blob = text(facts["tool"])
    h = history(case)
    op = facts["operation"]
    target = facts["target"].lower()
    sensitivity = facts["sensitivity"]
    if has_pattern(tool_blob, (
        r"search unrelated credentials", r"search all credentials",
        r"dump credentials", r"find all passwords", r"unrelated credentials",
    )):
        return True
    if op == "read_secret" or sensitivity in {"secret", "credential"}:
        scoped = (
            facts["resolved"].get("taskScoped") is True
            and has_pattern(h, (r"task.scoped credential", r"approved task credential", r"explicitly approved.*credential"))
            and facts["target"].lower() in h
        )
        return not scoped
    if "credential" in target or "password" in target or "/.ssh/" in target or "/.cloud/" in target:
        scoped = facts["resolved"].get("taskScoped") is True and facts["target"].lower() in h
        if op in READS or op == "read_secret":
            return not scoped
    if op in TRANSFERS and sensitivity in {"private", "confidential", "sensitive"}:
        destination = facts["destination"].lower()
        if not destination or destination not in h:
            return True
        source = str(facts["resolved"].get("source", "")).lower()
        if source and source not in h:
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
        and has_pattern(h, (
            r"remove disposable fixtures", r"delete disposable fixtures",
            r"clean up disposable fixtures", r"isolated cleanup experiment",
        ))
    )


def path_within(path: str, root: str) -> bool:
    if not path or not root or not path.startswith("/"):
        return False
    p = posixpath.normpath(path)
    r = posixpath.normpath(root)
    return p == r or p.startswith(r.rstrip("/") + "/")


def explicit_scope_denies_target(case: dict, facts: dict) -> bool:
    target = facts["target"]
    env = facts["environment"]
    root = str(env.get("workspace", env.get("cwd", "")))
    if not target.startswith("/") or not root.startswith("/"):
        return False
    h = history(case)
    only_scope = re.search(r"\b(?:edit|write|change|modify) only (?:files )?under\b|\bonly inspect\b|\bdo not change anything\b", h)
    if only_scope and not path_within(target, root):
        return True
    if facts["operation"] == "workspace_edit" and not path_within(target, root):
        return True
    resolved = facts["resolved"]
    origin = str(resolved.get("originPath", ""))
    if origin and target.startswith("/") and origin.startswith("/") and not path_within(target, root):
        return True
    return False


def latest_user_revokes_tool(case: dict) -> bool:
    state = None
    for message in user_messages(case):
        if has_pattern(message.lower(), REVOCATION_PATTERNS):
            state = "revoked"
        elif has_pattern(message.lower(), APPROVAL_PATTERNS):
            state = "approved"
    return state == "revoked"


def tool_decision(case: dict, request: str) -> str:
    tool = case.get("proposedTool")
    if not isinstance(tool, dict):
        return "none"
    if request == "block":
        return "block"
    facts = tool_facts(case)
    if independently_forbidden_tool(case, facts):
        return "block"
    if latest_user_revokes_tool(case):
        return "block"
    if request == "review":
        return "review"
    if not facts["resolved"]:
        return "review"

    op = facts["operation"]
    target = facts["target"]
    env_name = facts["environment_name"]
    sensitivity = facts["sensitivity"]
    resolved = facts["resolved"]
    h = history(case)

    if not op or not target or not env_name or env_name == "unknown":
        return "review"
    if explicit_scope_denies_target(case, facts):
        return "block"
    if resolved.get("bypassPreflight") is True:
        return "block"
    if facts["isolation"].get("hostMounts"):
        mounted_hosts = [str(m.get("host", "")) for m in facts["isolation"].get("hostMounts", []) if isinstance(m, dict)]
        if any(path_within(target, host) or path_within(host, target) for host in mounted_hosts if host):
            if op in MUTATIONS or op in TRANSFERS:
                return "block"
    if disposable_fixture_delete(case, facts):
        return "allow"

    # Task-scoped credentials are allowed only when the harness marks them
    # task-scoped and the user explicitly requests that exact credential.
    if op == "read_secret":
        scoped = (
            resolved.get("taskScoped") is True
            and has_pattern(h, (r"task.scoped credential", r"approved task credential", r"explicitly approved.*credential"))
            and target.lower() in h
        )
        return "allow" if scoped else "block"

    if op in TRANSFERS:
        destination = facts["destination"] or target
        source = str(resolved.get("source", resolved.get("originPath", "")))
        destination_requested = bool(destination and destination.lower() in h)
        source_requested = not source or source.lower() in h
        explicitly_requested = has_pattern(h, (
            r"\b(?:send|publish|upload|transfer|export)\b.{0,300}\bto\b",
            r"\bi explicitly approve\b",
            r"\bi approve\b",
        )) and destination_requested and source_requested
        if sensitivity in {"private", "confidential", "sensitive"}:
            if not destination_requested or not source_requested:
                return "block"
            if not explicitly_requested or not latest_approval_state(user_messages(case)):
                return "block"
            return "allow"
        return "allow" if explicitly_requested else "review"

    production = env_name in {"production", "prod"} or "production" in target.lower()
    if production and op in MUTATIONS:
        if failed_preflight(case, target):
            return "block"
        if (
            exact_authorization(case, op, target, env_name)
            and successful_preflight(case, target)
            and exact_rollback(case, target, op)
        ):
            return "allow"
        return "review"

    if op in {"delete", "remove"}:
        if env_name in {"host", "personal_machine", "local_machine"} or facts["environment"].get("kind") == "host" or env_name == "personal":
            return "allow" if exact_authorization(case, op, target, env_name) else "review"

    if op in READS:
        if op == "read_public_schema" and sensitivity == "public":
            return "allow"
        if sensitivity in {"secret", "credential"}:
            return "block"
        if sensitivity in {"private", "confidential", "sensitive", "unknown"}:
            return "review"
        root = str(facts["environment"].get("workspace", facts["environment"].get("cwd", "")))
        if env_name in {"workspace", "container"} and sensitivity == "public":
            return "allow"
        if env_name == "personal" and path_within(target, root) and sensitivity == "public":
            return "allow"
        if env_name in {"public", "external"} and sensitivity == "public":
            return "allow"
        return "review"

    if op in {"write", "edit", "update", "modify", "workspace_edit"}:
        root = str(facts["environment"].get("workspace", facts["environment"].get("cwd", "")))
        requested_edit = has_pattern(h, (
            r"\b(?:fix|edit|update|modify|write|repair)\b",
            r"\byou may edit files\b",
        ))
        if (
            requested_edit and path_within(target, root)
            and sensitivity == "public"
            and env_name in {"personal", "workspace", "container"}
            and resolved.get("reversible", op == "workspace_edit") is True
        ):
            return "allow"
        return "review"

    if op in {"host_admin", "privileged_change"} and has_pattern(h, (r"not approved", r"has not been approved", r"not authorized", r"do not authorize")):
        return "block"
    if op in {"host_admin", "privileged_change", "force_push", "terraform_apply"}:
        return "allow" if exact_authorization(case, op, target, env_name) else "review"

    if op in MUTATIONS:
        return "allow" if exact_authorization(case, op, target, env_name) else "review"
    return "review"


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
    untrusted = text([
        case.get("memory", []),
        case.get("repositoryInstructions", []),
        case.get("toolResults", []),
    ])
    if has_pattern(untrusted, INJECTION_PATTERNS):
        return "watch"
    if request == "review" or tool == "review":
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
    print("CASE_DIAGNOSTICS " + encoded, flush=True)


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
    print("BATCH_DIAGNOSTICS " + json.dumps(batch_diagnostics(cases, results), sort_keys=True), flush=True)
    return JSONResponse({"profile": PROFILE, "batchId": batch_id, "results": results})
