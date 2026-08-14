#!/usr/bin/env python3
# ruff: noqa: ANN001, ANN201, D101, D103, EM101, EM102, N999, RUF100, TRY003
# pylint: disable=invalid-name,too-many-branches,broad-exception-caught,import-error
# fmt: off
"""Fail-closed authorization for Zizmor self-hosted-runner findings."""

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

import yaml

POLICY_SCHEMA_VERSION = 3
DOCKER_POLICY = {
    "socket": "/run/docker.sock",
    "minimum_version": "29.2.1",
    "target_version": "29.7.2",
}

TOP_FIELDS = {
    "schema_version",
    "docker",
    "defaults",
    "profiles",
    "hosted_exceptions",
    "repositories",
}
JOB_FIELDS = {
    "runs_on",
    "environment",
    "permissions",
    "allowed_secrets",
    "triggers",
    "if",
}
SECRET_RE = re.compile(
    r"\bsecrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)\b|"
    r"\[\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\2\s*\])"
)
SECRET_CONTEXT_RE = re.compile(r"\bsecrets\b")
EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
FORBIDDEN_TRIGGERS = {"pull_request_target", "workflow_run", "repository_dispatch"}
ALLOWED_TRIGGERS = {"schedule", "workflow_dispatch", "push", "pull_request"}
ALLOWED_PERMISSIONS = {
    "contents": {"read", "none"},
    "checks": {"write", "read", "none"},
}
ZIZMOR_EXIT_BY_SEVERITY = {
    "Informational": 11,
    "Low": 12,
    "Medium": 13,
    "High": 14,
}


class PolicyError(ValueError):
    pass


def validate_zizmor_result(exit_code, findings):
    """Validate Zizmor's documented findings exit contract before authorization."""
    if not isinstance(findings, list):
        raise PolicyError("Zizmor output must be a JSON array")
    if not findings:
        if exit_code != 0:
            raise PolicyError("Zizmor empty output requires exit 0")
        return
    if exit_code == 0:
        raise PolicyError("Zizmor exit 0 requires an empty finding array")

    expected_exit = 0
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise PolicyError(f"Zizmor finding {index} must be an object")
        determinations = finding.get("determinations")
        if not isinstance(determinations, dict):
            raise PolicyError(f"Zizmor finding {index} determinations must be an object")
        severity = determinations.get("severity")
        if severity not in ZIZMOR_EXIT_BY_SEVERITY:
            raise PolicyError(f"Zizmor finding {index} has invalid severity: {severity!r}")
        expected_exit = max(expected_exit, ZIZMOR_EXIT_BY_SEVERITY[severity])

    if exit_code != expected_exit:
        raise PolicyError(
            f"Zizmor findings require exit {expected_exit}, received {exit_code}"
        )


def strict_object(value, allowed, context):
    if not isinstance(value, dict):
        raise PolicyError(f"{context} must be an object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise PolicyError(f"{context} has unknown fields: {sorted(unknown)}")
    return value


def governed_repositories(path):
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        repos = raw["repo_classes"]["repos"]
    except Exception as exc:
        raise PolicyError(f"cannot read governance inventory {path}: {exc}") from exc
    valid_mapping = isinstance(repos, dict) and bool(repos)
    valid_entries = valid_mapping and all(
        isinstance(name, str) and isinstance(repo_class, str)
        for name, repo_class in repos.items()
    )
    if not valid_entries:
        raise PolicyError(
            "governance repo_classes.repos must be a non-empty string mapping"
        )
    return {f"f5-sales-demo/{name}" for name in repos}


def repository_runner_profiles(workflows, profiles, default_profile):
    runner = workflows.get("runner", {})
    if not isinstance(runner, dict) or set(runner) - {"profiles"}:
        raise PolicyError("repository runner policy must contain only profiles")
    allowed = runner.get("profiles", [default_profile])
    valid_profiles = isinstance(allowed, list) and bool(allowed)
    known_profiles = valid_profiles and all(
        isinstance(profile, str) and profile in profiles for profile in allowed
    )
    unique_profiles = known_profiles and len(set(allowed)) == len(allowed)
    required_profiles = unique_profiles and {
        default_profile,
        "container-build",
    }.issubset(allowed)
    if not required_profiles:
        raise PolicyError(
            "repository runner profiles must be a unique array of existing profiles "
            "that includes the default and container-build"
        )
    return allowed


def canonical_routes(basename, allowed_profiles):
    return tuple(
        ["self-hosted", "Linux", "X64", repository_label, profile]
        for profile in allowed_profiles
        for repository_label in (basename, "${{ github.event.repository.name }}")
    )


def permissions_within_ceiling(permissions, context):
    if not isinstance(permissions, dict):
        raise PolicyError(f"{context} must be an object")
    for scope, access in permissions.items():
        if scope not in ALLOWED_PERMISSIONS or access not in ALLOWED_PERMISSIONS[scope]:
            raise PolicyError(
                f"{context} exceeds the permission ceiling: {scope}={access}"
            )


def load_policy(path, governance_path, repository):
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    strict_object(raw, TOP_FIELDS, "policy")
    if raw.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise PolicyError(f"unsupported schema_version: {raw.get('schema_version')!r}")
    if raw.get("docker") != DOCKER_POLICY:
        raise PolicyError(f"policy docker contract must equal {DOCKER_POLICY!r}")
    repositories = raw.get("repositories")
    governed = governed_repositories(governance_path)
    if not isinstance(repositories, dict) or set(repositories) != governed:
        missing = (
            sorted(governed - set(repositories or {}))
            if isinstance(repositories, dict)
            else sorted(governed)
        )
        extra = (
            sorted(set(repositories or {}) - governed)
            if isinstance(repositories, dict)
            else []
        )
        raise PolicyError(
            f"policy/governance repository mismatch: missing={missing}, extra={extra}"
        )
    if repository not in repositories:
        raise PolicyError(f"repository {repository!r} is not present in policy")
    profiles = raw.get("profiles")
    default_profile = raw.get("defaults", {}).get("profile")
    if (
        not isinstance(profiles, dict)
        or not isinstance(default_profile, str)
        or default_profile not in profiles
    ):
        raise PolicyError("policy default profile must name an existing profile")
    result = {}
    workflows = repositories[repository]
    if not isinstance(workflows, dict):
        raise PolicyError("repository policy must be a workflow object")
    allowed_profiles = repository_runner_profiles(
        workflows, profiles, default_profile
    )
    for workflow, jobs in workflows.items():
        if workflow == "runner":
            continue
        if not isinstance(workflow, str) or not workflow.startswith(
            ".github/workflows/"
        ):
            raise PolicyError(f"invalid workflow key: {workflow!r}")
        if not isinstance(jobs, dict) or not jobs:
            raise PolicyError(f"{workflow} must contain jobs")
        for job_id, spec in jobs.items():
            strict_object(spec, JOB_FIELDS, f"{workflow}/{job_id}")
            if set(spec) != JOB_FIELDS:
                raise PolicyError(
                    f"{workflow}/{job_id} must define exactly {sorted(JOB_FIELDS)}"
                )
            labels = spec["runs_on"]
            if not isinstance(labels, list) or not all(
                isinstance(x, str) for x in labels
            ):
                raise PolicyError(f"{workflow}/{job_id}.runs_on must be a string array")
            if not isinstance(spec["permissions"], dict):
                raise PolicyError(f"{workflow}/{job_id}.permissions must be an object")
            permissions_within_ceiling(
                spec["permissions"], f"{workflow}/{job_id}.permissions"
            )
            if (
                not isinstance(spec["allowed_secrets"], list)
                or not all(
                    isinstance(secret, str)
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", secret)
                    for secret in spec["allowed_secrets"]
                )
                or len(set(spec["allowed_secrets"])) != len(spec["allowed_secrets"])
            ):
                raise PolicyError(
                    f"{workflow}/{job_id}.allowed_secrets must be a unique array"
                )
            if not isinstance(spec["triggers"], dict) or not all(
                isinstance(x, str) for x in spec["triggers"]
            ):
                raise PolicyError(
                    f"{workflow}/{job_id}.triggers must be an exact trigger mapping"
                )
            unknown_triggers = set(spec["triggers"]) - ALLOWED_TRIGGERS
            if unknown_triggers:
                raise PolicyError(
                    f"{workflow}/{job_id} has untrusted trigger(s): {sorted(unknown_triggers)}"
                )
            result[(workflow, job_id)] = spec
    return result, default_profile, allowed_profiles


def route_component(item):
    if isinstance(item, dict) and set(item) == {"Key"} and isinstance(item["Key"], str):
        return item["Key"]
    raise PolicyError(f"malformed route component: {item!r}")


def normalize_location(location):
    if not isinstance(location, dict):
        raise PolicyError("location must be an object")
    symbolic = location.get("symbolic")
    if not isinstance(symbolic, dict):
        raise PolicyError("location.symbolic is missing")
    key = symbolic.get("key")
    if not isinstance(key, dict) or set(key) != {"Local"}:
        raise PolicyError("location.symbolic.key must identify exactly one Local path")
    local = key.get("Local")
    if not isinstance(local, dict) or set(local) != {"verbatim_path"}:
        raise PolicyError("location Local key must contain only verbatim_path")
    path = local.get("verbatim_path") if isinstance(local, dict) else None
    if not isinstance(path, str):
        raise PolicyError("location.symbolic.key.Local.verbatim_path is missing")
    route_container = symbolic.get("route")
    route = route_container.get("route") if isinstance(route_container, dict) else None
    if not isinstance(route, list):
        raise PolicyError("location.symbolic.route.route must be an array")
    parts = [route_component(item) for item in route]
    if parts.count("jobs") != 1:
        raise PolicyError(f"route must contain exactly one jobs component: {parts}")
    index = parts.index("jobs")
    if index + 2 >= len(parts) or parts[index + 2 :] != ["runs-on"]:
        raise PolicyError(f"route must identify exactly one job runs-on: {parts}")
    normalized = PurePosixPath(path).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    path_parts = PurePosixPath(normalized).parts
    if PurePosixPath(normalized).is_absolute() or ".." in path_parts:
        raise PolicyError(
            f"finding path is not a safe repository-relative path: {path!r}"
        )
    workflow_roots = (".github/workflows/", "workflows/")
    if not normalized.startswith(workflow_roots):
        raise PolicyError(f"finding path is outside governed workflow roots: {normalized!r}")
    return normalized, parts[index + 1], parts


def workflow_on(workflow):
    return workflow.get("on", workflow.get(True))


def trigger_names(workflow):
    value = workflow_on(workflow)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return sorted(value)
    if isinstance(value, dict) and all(isinstance(x, str) for x in value):
        return sorted(value)
    raise PolicyError("workflow on must be a string, string array, or mapping")


def effective_permissions(workflow, job):
    value = job.get("permissions", workflow.get("permissions"))
    if value is None:
        raise PolicyError("effective permissions are implicit")
    if isinstance(value, str) and value in {"read-all", "write-all"}:
        raise PolicyError("permissions shortcuts are forbidden")
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and v in {"read", "write", "none"} for k, v in value.items()
    ):
        raise PolicyError("effective permissions must be an explicit scope mapping")
    permissions_within_ceiling(value, "effective permissions")
    return value


def strip_wrapping_parentheses(expression):
    expression = expression.strip()
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        wraps_all = True
        for index, character in enumerate(expression):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth < 0:
                    return expression
                if depth == 0 and index != len(expression) - 1:
                    wraps_all = False
                    break
        if depth != 0 or not wraps_all:
            break
        expression = expression[1:-1].strip()
    return expression


def split_boolean(expression, operator):
    parts = []
    depth = 0
    start = 0
    index = 0
    while index < len(expression):
        character = expression[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise PolicyError("job if expression has unbalanced parentheses")
        elif depth == 0 and expression.startswith(operator, index):
            parts.append(expression[start:index].strip())
            start = index + len(operator)
            index += len(operator) - 1
        index += 1
    if depth != 0:
        raise PolicyError("job if expression has unbalanced parentheses")
    parts.append(expression[start:].strip())
    return parts


def condition_excludes_pull_request(expression):
    """Conservatively prove every branch excludes pull_request execution."""
    if not isinstance(expression, str) or "${{" in expression:
        return False
    expression = strip_wrapping_parentheses(expression)
    if expression == "github.event_name != 'pull_request'":
        return True
    disjunction = split_boolean(expression, "||")
    if len(disjunction) > 1:
        return all(condition_excludes_pull_request(branch) for branch in disjunction)
    conjunction = split_boolean(expression, "&&")
    if len(conjunction) > 1:
        return any(condition_excludes_pull_request(branch) for branch in conjunction)
    return False


def walk(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, (*path, str(index)))
    elif isinstance(value, str):
        yield path, value


def secret_references(text):
    names = set()
    for expression in EXPRESSION_RE.finditer(text):
        body = expression.group(1)
        covered = []
        for match in SECRET_RE.finditer(body):
            names.add(match.group(1) or match.group(3))
            covered.append(match.span())
        for context in SECRET_CONTEXT_RE.finditer(body):
            if not any(
                start <= context.start() and context.end() <= end
                for start, end in covered
            ):
                raise PolicyError(
                    "dynamic or malformed secrets expression is forbidden"
                )
    return names


def validate_job(repository, workflow, job, spec, default_profile):
    errors = []
    basename = repository.split("/", 1)[1]
    runs_on = job.get("runs-on")
    expected_labels = [
        "self-hosted",
        "Linux",
        "X64",
        basename,
        default_profile,
    ]
    if runs_on != spec["runs_on"] or runs_on != expected_labels:
        errors.append(f"runs-on must equal {expected_labels!r}, got {runs_on!r}")
    if job.get("environment") != spec["environment"]:
        errors.append(f"environment mismatch: {job.get('environment')!r}")
    try:
        permissions = effective_permissions(workflow, job)
        if permissions != spec["permissions"]:
            errors.append(f"permissions mismatch: {permissions!r}")
    except PolicyError as exc:
        errors.append(str(exc))
    try:
        triggers = trigger_names(workflow)
        if triggers != sorted(spec["triggers"]):
            errors.append(f"trigger mismatch: {triggers!r}")
        if workflow_on(workflow) != spec["triggers"]:
            errors.append("complete trigger structure does not exactly match policy")
        if set(triggers) & FORBIDDEN_TRIGGERS:
            errors.append(
                f"forbidden trigger(s): {sorted(set(triggers) & FORBIDDEN_TRIGGERS)}"
            )
        unknown_triggers = set(triggers) - ALLOWED_TRIGGERS
        if unknown_triggers:
            errors.append(f"untrusted trigger(s): {sorted(unknown_triggers)}")
        on = workflow_on(workflow)
        if "push" in triggers:
            push = on.get("push") if isinstance(on, dict) else None
            if not isinstance(push, dict) or push.get("branches") != ["main"]:
                errors.append("push must be bounded exactly to main")
    except PolicyError as exc:
        errors.append(str(exc))
    if job.get("if") != spec["if"]:
        errors.append("job if expression does not exactly match policy")
    if "pull_request" in trigger_names(
        workflow
    ) and not condition_excludes_pull_request(job.get("if")):
        errors.append("job if does not provably exclude pull_request execution")
    references = set()
    for path, text in walk(job):
        try:
            names = secret_references(text)
        except PolicyError as exc:
            errors.append(f"{exc} at {'.'.join(path)}")
            continue
        references.update(names)
        if names and ("run" in path or not ({"env", "with"} & set(path))):
            errors.append(f"secret reference in unsupported location {'.'.join(path)}")
    if references != set(spec["allowed_secrets"]):
        errors.append(f"secret set mismatch: {sorted(references)!r}")
    for step in job.get("steps", []):
        if (
            isinstance(step, dict)
            and isinstance(step.get("uses"), str)
            and step["uses"].split("@", 1)[0] == "actions/checkout"
            and step.get("with", {}).get("persist-credentials") is not False
        ):
            errors.append(  # noqa: PERF401 - conditional validation is clearer inline
                "checkout must use literal persist-credentials: false"
            )
    return errors


def inventory(root, repository, policy, default_profile, allowed_profiles):
    actual = {}
    paths = (
        *(root / ".github/workflows").glob("*.y*ml"),
        *(root / "workflows").glob("*.y*ml"),
    )
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        try:
            workflow = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            raise PolicyError(f"cannot parse {relative}: {exc}") from exc
        if not isinstance(workflow, dict) or not isinstance(
            workflow.get("jobs", {}), dict
        ):
            raise PolicyError(f"malformed workflow {relative}")
        basename = repository.split("/", 1)[1]
        for job_id, job in workflow.get("jobs", {}).items():
            if not isinstance(job, dict):
                raise PolicyError(f"malformed job {relative}/{job_id}")
            runs_on = job.get("runs-on")
            self_hosted = isinstance(runs_on, list) and "self-hosted" in runs_on
            suspicious = isinstance(runs_on, str) and "self-hosted" in runs_on
            if suspicious:
                raise PolicyError(
                    f"expression or scalar self-hosted runs-on at {relative}/{job_id}"
                )
            if self_hosted:
                key = (relative, job_id)
                if key in policy:
                    errors = validate_job(
                        repository, workflow, job, policy[key], default_profile
                    )
                    if errors:
                        raise PolicyError(
                            f"{relative}/{job_id}: " + "; ".join(errors)
                        )
                elif runs_on not in canonical_routes(basename, allowed_profiles):
                    raise PolicyError(
                        f"{relative}/{job_id}: runs-on must use the canonical repository route"
                    )
                actual[key] = workflow
    unused = sorted(set(policy) - set(actual))
    if unused:
        raise PolicyError(f"unused policy entries: {unused}")
    return set(actual)


def validate(findings, root, repository, policy_path, governance_path):
    if not isinstance(findings, list):
        raise PolicyError("Zizmor output must be a JSON array")
    policy, default_profile, allowed_profiles = load_policy(
        policy_path, governance_path, repository
    )
    actual = inventory(
        root, repository, policy, default_profile, allowed_profiles
    )
    found = []
    routes = []
    for finding in findings:
        ident = finding.get("ident") if isinstance(finding, dict) else None
        if ident != "self-hosted-runner":
            raise PolicyError(f"unapproved finding: {ident!r}")
        locations = finding.get("locations") if isinstance(finding, dict) else None
        if not isinstance(locations, list) or len(locations) != 1:
            raise PolicyError("each finding must have exactly one location")
        workflow, job_id, route = normalize_location(locations[0])
        key = (workflow, job_id)
        if key not in actual:
            raise PolicyError(f"finding route is not approved: {workflow}/{job_id}")
        found.append(key)
        routes.append((workflow, job_id, route))
    counts = Counter(found)
    duplicates = sorted(key for key, count in counts.items() if count != 1)
    if duplicates:
        raise PolicyError(f"duplicate findings: {duplicates}")
    if set(found) != actual:
        raise PolicyError(
            f"finding/job mismatch: missing={sorted(actual - set(found))}, extra={sorted(set(found) - actual)}"
        )
    return routes


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--zizmor-exit", type=int, required=True)
    parser.add_argument("findings", type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.repository or args.repository.count("/") != 1:
        print(
            "workflow security validation failed: "
            "an exact --repository owner/name is required",
            file=sys.stderr,
        )
        return 1
    try:
        findings = json.loads(args.findings.read_text(encoding="utf-8"))
        validate_zizmor_result(args.zizmor_exit, findings)
        routes = validate(
            findings, Path.cwd(), args.repository, args.policy, args.governance
        )
    except (OSError, ValueError) as exc:
        print(f"workflow security validation failed: {exc}", file=sys.stderr)
        return 1
    for workflow, job_id, route in routes:
        print(
            f"approved {args.repository}:{workflow}:{job_id} route={json.dumps(route)}"
        )
    print(f"validated {len(routes)} governed self-hosted-runner finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
