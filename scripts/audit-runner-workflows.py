#!/usr/bin/env python3
# ruff: noqa: ANN001, ANN201, ARG001, D103, EM101, EM102, N999, PLR2004, RUF100, TRY003
# pylint: disable=invalid-name,too-many-branches
"""Fail closed when workflow routing or remote action pins escape fleet policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml  # pylint: disable=import-error

SHA_RE = re.compile(r"[0-9a-f]{40}")
CANONICAL_REPOSITORY_LABEL = "${{ github.event.repository.name }}"
PULL_REQUEST_EVENT = "github.event_name == 'pull_request' && "
PULL_REQUEST_HEAD_REPO = "github.event.pull_request.head.repo.full_name"
PULL_REQUEST_SOURCE = PULL_REQUEST_HEAD_REPO + " == github.repository"
PULL_REQUEST_GUARD = PULL_REQUEST_EVENT + PULL_REQUEST_SOURCE
CALLABLE_DOCKER_GUARD = (
    "github.event_name == 'workflow_dispatch' || "
    "(github.event_name == 'pull_request' && "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
DEFAULT_BRANCH_DOCKER_GUARD = (
    "github.event_name == 'workflow_dispatch' || "
    "(github.event_name == 'push' && "
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)) || "
    "(github.event_name == 'pull_request' && "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)


class AuditError(ValueError):
    """A deterministic workflow policy violation."""


def workflow_on(value):
    return value.get("on", value.get(True)) if isinstance(value, dict) else None


def load_policy(path, repository):
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuditError(f"cannot read runner policy: {exc}") from exc
    if raw.get("schema_version") != 3:
        raise AuditError("runner policy schema_version must be 3")
    repositories = raw.get("repositories")
    if not isinstance(repositories, dict) or repository not in repositories:
        raise AuditError(f"repository is not governed: {repository}")
    profiles = raw.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise AuditError("runner policy profiles must be a non-empty object")
    exceptions = raw.get("hosted_exceptions", {}).get(repository, {})
    if not isinstance(exceptions, dict):
        raise AuditError("repository hosted exceptions must be an object")
    return raw, exceptions


def remote_dependency(value):
    if not isinstance(value, str):
        raise AuditError(f"uses must be a string, got {value!r}")
    if value.startswith(("./", "docker://")):
        return None
    if "@" not in value:
        raise AuditError(f"remote action has no revision: {value}")
    _, revision = value.rsplit("@", 1)
    if not SHA_RE.fullmatch(revision):
        raise AuditError(f"remote action is not commit-pinned: {value}")
    return value


def expected_self_hosted_labels(profile, profiles):
    labels = ["self-hosted", "Linux", "X64", CANONICAL_REPOSITORY_LABEL]
    if profile:
        if profile not in profiles:
            raise AuditError(f"unknown runner profile: {profile}")
        labels.extend(profiles[profile].get("labels", []))
    return labels


def docker_socket_value(profiles, profile):
    spec = profiles.get(profile)
    return spec.get("docker_socket") if isinstance(spec, dict) else None


def profile_for_route(runs_on, profiles):
    """Resolve one security-equivalent profile for an exact scheduling route."""
    if not isinstance(runs_on, list) or len(runs_on) != 5:
        return None
    candidates = []
    for name, spec in profiles.items():
        if runs_on[-1] in spec.get("labels", []):
            candidates.append((name, spec))
    if not candidates:
        return None
    reference = candidates[0][1]
    if not all(spec == reference for _, spec in candidates[1:]):
        return None
    return candidates[0][0]


def exception_for(exceptions, relative, job_id):
    workflow = exceptions.get(relative, {})
    if not isinstance(workflow, dict):
        raise AuditError(f"hosted exception workflow must be an object: {relative}")
    return workflow.get(job_id)


def trigger_names(workflow):
    value = workflow_on(workflow)
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    if isinstance(value, dict) and all(isinstance(item, str) for item in value):
        return set(value)
    raise AuditError("workflow trigger is malformed")


def audit_docker_route(workflow, job, profiles, profile):
    errors: list[str] = []
    if profile not in profiles or not profiles[profile].get("docker_socket"):
        return errors
    try:
        triggers = trigger_names(workflow)
    except AuditError as exc:
        return [f"Docker-capable job has a malformed trigger: {exc}"]
    allowed = {"pull_request", "push", "workflow_call", "workflow_dispatch"}
    if not triggers or not triggers <= allowed:
        errors.append(
            "Docker-capable jobs require a protected push, same-repository PR, or manual dispatch",
        )
        return errors
    if triggers == {"workflow_dispatch"}:
        return errors
    if triggers == {"pull_request"}:
        expected_guard = PULL_REQUEST_GUARD
    elif "push" in triggers or triggers == {"workflow_call"}:
        expected_guard = DEFAULT_BRANCH_DOCKER_GUARD
    else:
        expected_guard = CALLABLE_DOCKER_GUARD
    if job.get("if") != expected_guard:
        errors.append(
            "Docker-capable PR job requires the complete same-repository guard",
        )
    needs = job.get("needs")
    needs_is_trust_gate_list = isinstance(needs, list) and needs == ["trust-gate"]
    if needs != "trust-gate" and not needs_is_trust_gate_list:
        errors.append("Docker-capable PR job requires the socketless trust-gate")
    trust_gate = workflow.get("jobs", {}).get("trust-gate")
    trust_runs_on = trust_gate.get("runs-on") if isinstance(trust_gate, dict) else None
    trust_profile = profile_for_route(trust_runs_on, profiles)
    if docker_socket_value(profiles, trust_profile) is not False:
        errors.append("Docker-capable PR job requires a socketless trust-gate job")
    return errors


def step_requires_docker(step):
    """Return whether an executable step needs the Docker socket, not comments."""
    if not isinstance(step, dict):
        return False
    uses = step.get("uses")
    docker_uses = ("docker://", "docker/", "super-linter/super-linter@")
    if isinstance(uses, str) and uses.startswith(docker_uses):
        return True
    run = step.get("run")
    if not isinstance(run, str):
        return False
    executable = "\n".join(line.split("#", 1)[0] for line in run.splitlines())
    return bool(re.search(r"(?<![\w-])docker(?:\s|$)", executable))


def step_has_privileged_package_install(step):
    """Reject self-hosted provisioning assumptions in executable shell content."""
    if not isinstance(step, dict) or not isinstance(step.get("run"), str):
        return False
    executable = "\n".join(line.split("#", 1)[0] for line in step["run"].splitlines())
    return bool(
        re.search(r"(?<![\w-])sudo(?:\s|$)", executable)
        or re.search(r"(?<![\w-])apt(?:-get)?\s+(?:update|install)(?:\s|$)", executable)
    )


def audit_job(  # pylint: disable=too-many-locals
    repository,
    relative,
    job_id,
    job,
    profiles,
    exceptions,
    workflow_context,
):
    default_profile, workflow = workflow_context
    errors = []
    if not isinstance(job, dict):
        return [f"{relative}/{job_id}: job must be an object"]
    if "uses" in job:
        try:
            remote_dependency(job["uses"])
        except AuditError as exc:
            errors.append(f"{relative}/{job_id}: {exc}")
        if "runs-on" in job:
            errors.append(
                f"{relative}/{job_id}: reusable-workflow job cannot set runs-on",
            )
        return errors
    runs_on = job.get("runs-on")
    exception = exception_for(exceptions, relative, job_id)
    if exception is not None:
        allowed = exception.get("runs_on") if isinstance(exception, dict) else None
        if allowed == "matrix":
            if not isinstance(runs_on, str) or "matrix." not in runs_on:
                errors.append(
                    f"{relative}/{job_id}: hosted exception requires matrix runs-on",
                )
        elif runs_on != allowed:
            errors.append(
                f"{relative}/{job_id}: hosted runs-on {runs_on!r} does not match {allowed!r}",
            )
        reason = exception.get("reason") if isinstance(exception, dict) else None
        if not isinstance(reason, str) or len(reason.strip()) < 12:
            errors.append(f"{relative}/{job_id}: hosted exception reason is incomplete")
    else:
        profile = default_profile
        if isinstance(runs_on, list) and len(runs_on) == 5:
            profile = profile_for_route(runs_on, profiles)
        try:
            expected = expected_self_hosted_labels(profile, profiles)
        except AuditError as exc:
            errors.append(f"{relative}/{job_id}: {exc}")
            expected = []
        static = list(expected)
        if len(static) >= 4:
            static[3] = repository.split("/", 1)[1]
        if runs_on not in (expected, static):
            errors.append(
                f"{relative}/{job_id}: runs-on must use the canonical repository route, got {runs_on!r}",
            )
        steps = job.get("steps", [])
        requires_docker = any(map(step_requires_docker, steps))
        profile_has_socket = docker_socket_value(profiles, profile) is True
        if requires_docker and not profile_has_socket:
            errors.append(
                f"{relative}/{job_id}: Docker workload requires a Docker socket profile",
            )
        route_errors = audit_docker_route(workflow, job, profiles, profile)
        route_prefix = f"{relative}/{job_id}: "
        errors.extend(route_prefix + error for error in route_errors)
        if any(map(step_has_privileged_package_install, steps)):
            errors.append(
                f"{relative}/{job_id}: self-hosted jobs cannot use sudo or apt package installation",
            )
    for index, step in enumerate(job.get("steps", [])):
        if not isinstance(step, dict) or "uses" not in step:
            continue
        try:
            remote_dependency(step["uses"])
        except AuditError as exc:
            errors.append(f"{relative}/{job_id}/steps/{index}: {exc}")
    return errors


def audit_repository(root, repository, policy_path):
    root = Path(root)
    policy, exceptions = load_policy(policy_path, repository)
    profiles = policy["profiles"]
    errors = []
    actual_exceptions = set()
    workflows = root / ".github/workflows"
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        relative = path.relative_to(root).as_posix()
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{relative}: cannot parse workflow: {exc}")
            continue
        if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
            errors.append(f"{relative}: workflow must contain a jobs object")
            continue
        if workflow_on(document) is None:
            errors.append(f"{relative}: workflow trigger is missing")
        for job_id, job in document["jobs"].items():
            if exception_for(exceptions, relative, job_id) is not None:
                actual_exceptions.add((relative, job_id))
            errors.extend(
                audit_job(
                    repository,
                    relative,
                    job_id,
                    job,
                    profiles,
                    exceptions,
                    (policy["defaults"]["profile"], document),
                )
            )
    declared_exceptions = set()
    for workflow, jobs in exceptions.items():
        for job_id in jobs:
            declared_exceptions.add((workflow, job_id))
    for workflow, job_id in sorted(declared_exceptions - actual_exceptions):
        errors.append(f"unused hosted exception: {workflow}/{job_id}")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(".github/config/self-hosted-runner-policy.json"),
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        errors = audit_repository(args.root, args.repository, args.policy)
    except AuditError as exc:
        errors = [str(exc)]
    if args.json:
        print(json.dumps({"repository": args.repository, "errors": errors}, indent=2))
    else:
        for error in errors:
            print(f"::error::{error}", file=sys.stderr)
        if not errors:
            message = "validated workflow routing and immutable pins"
            print(f"{message} for {args.repository}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
