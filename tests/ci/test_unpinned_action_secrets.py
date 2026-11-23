#!/usr/bin/env python3
"""Fail while a scheduled or otherwise automatic job runs a movable third-party
action that can read secrets.

The runner at actions/runner v2.338.2 sends the action ref string, including a
tag, to ResolveActionDownloadInfo and then runs the commit that comes back
(ActionManager.GetDownloadInfoAsync / DownloadRepositoryActionAsync). A tag is
a git ref and moves when it is updated. A 40-hex commit SHA does not.

Evaluated inputs are copied into the composite action's inputs context, and
the github context includes the job token (ExecutionContext, CompositeActionHandler).
Step env expressions are evaluated and passed to the step process
(CompositeActionHandler, ActionRunner, ScriptHandler). String equality in job
`if` conditions is ordinal-ignore-case (EvaluationResult.AbstractEqual).

These tests drive that sequence against the workflows in this tree. They fail
while a movable ref is what the job runs, and pass once every such step is
pinned to a full commit SHA and the Coverity job declares read-only token
permissions.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")

# Placeholder values only. These are not credentials.
PLACEHOLDERS = {
    "COVERITY_SCAN_TOKEN": "placeholder-coverity-scan-token",
    "COVERITY_SCAN_EMAIL": "placeholder-coverity-scan-email",
    "MEMBROWSE_API_KEY": "placeholder-membrowse-api-key",
    "GITHUB_TOKEN": "placeholder-github-token",
}

# actions/* is published by GitHub. Those tags are left to a separate check.
FIRST_PARTY_OWNERS = {"actions"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
WRITE_RE = re.compile(r"write", re.IGNORECASE)


def load_workflow(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    # PyYAML 1.1 parses the bare key "on" as boolean true.
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def abstract_equal(left, right):
    """StringComparison.OrdinalIgnoreCase, as in EvaluationResult.AbstractEqual."""
    return str(left).lower() == str(right).lower()


def job_if_selects_owner(job, repository_owner):
    """Return true when the job's if condition accepts this repository owner.

    A missing if selects the job. The Coverity condition is a single
    github.repository_owner comparison. Anything else is treated as selected
    so a parse gap cannot hide a step that still runs.
    """
    condition = job.get("if")
    if condition is None:
        return True
    text = str(condition).strip()
    match = re.fullmatch(
        r"github\.repository_owner\s*==\s*['\"]([^'\"]+)['\"]",
        text,
    )
    if not match:
        return True
    return abstract_equal(repository_owner, match.group(1))


def split_uses(uses):
    if not isinstance(uses, str):
        return None
    if uses.startswith("./") or uses.startswith("docker://"):
        return None
    if "@" not in uses:
        return None
    name, ref = uses.rsplit("@", 1)
    owner = name.split("/", 1)[0]
    return owner, name, ref


def step_secret_expressions(step):
    found = []

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            for expr in EXPR_RE.findall(node):
                expr = expr.strip()
                if expr.startswith("secrets."):
                    found.append(expr)

    walk(step.get("with") or {})
    walk(step.get("env") or {})
    return found


def secret_name(expr):
    # secrets.COVERITY_SCAN_TOKEN or secrets['COVERITY_SCAN_TOKEN']
    bracket = re.fullmatch(r"secrets\[['\"]([^'\"]+)['\"]\]", expr)
    if bracket:
        return bracket.group(1)
    if expr.startswith("secrets."):
        return expr.split(".", 1)[1]
    raise AssertionError("not a secrets expression: %s" % expr)


def iter_secret_actions():
    for path in sorted(os.listdir(WORKFLOWS)):
        if not path.endswith((".yml", ".yaml")):
            continue
        full = os.path.join(WORKFLOWS, path)
        workflow = load_workflow(full)
        for job_name, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            for index, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                parsed = split_uses(step.get("uses"))
                if parsed is None:
                    continue
                owner, name, ref = parsed
                if owner in FIRST_PARTY_OWNERS:
                    continue
                expressions = step_secret_expressions(step)
                if not expressions:
                    continue
                yield {
                    "file": path,
                    "job": job_name,
                    "index": index,
                    "uses": step.get("uses"),
                    "owner": owner,
                    "name": name,
                    "ref": ref,
                    "expressions": expressions,
                    "job_runs_for_wolfssl": job_if_selects_owner(job, "wolfSSL"),
                }


def git(repo, *args, check=True):
    result = subprocess.run(
        ["git", "-C", repo, *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            "git %s failed: %s" % (" ".join(args), result.stderr.strip())
        )
    return result


def write_action(repo, manifest, message):
    path = os.path.join(repo, "action.yml")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(manifest)
    git(repo, "add", "action.yml")
    git(repo, "commit", "-q", "-m", message)


def build_action_repo(refs):
    """Local stand-in for the action repository the runner resolves by ref.

    The published tag is created on a benign commit, then moved to a commit
    whose composite action reads inputs and github.token. That is the same
    ref update an action maintainer publishes.
    """
    repo = tempfile.mkdtemp(prefix="action-repo-")
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "actions-test@example.com")
    git(repo, "config", "user.name", "actions-test")
    benign = """name: benign
runs:
  using: composite
  steps:
    - shell: bash
      run: "true"
"""
    write_action(repo, benign, "benign action")
    benign_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    for ref in sorted(set(refs)):
        git(repo, "tag", "-f", ref, benign_sha)
    malicious = """name: moved-tag
description: Replacement published by moving the version tag.
inputs:
  token:
    required: false
  email:
    required: false
  api_key:
    required: false
  password:
    required: false
runs:
  using: composite
  steps:
    - shell: bash
      env:
        TOKEN: ${{ inputs.token }}
        EMAIL: ${{ inputs.email }}
        API_KEY: ${{ inputs.api_key }}
        PASSWORD: ${{ inputs.password }}
        GH_TOKEN: ${{ github.token }}
      run: |
        dest="$CAPTURE_FILE"
        : > "$dest"
        printf '%s\\n' "$TOKEN" >> "$dest"
        printf '%s\\n' "$EMAIL" >> "$dest"
        printf '%s\\n' "$API_KEY" >> "$dest"
        printf '%s\\n' "$PASSWORD" >> "$dest"
        printf '%s\\n' "$GH_TOKEN" >> "$dest"
"""
    write_action(repo, malicious, "moved tag")
    attacker_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    for ref in sorted(set(refs)):
        # A tag update, not a new immutable object named by the workflow.
        git(repo, "tag", "-f", ref, attacker_sha)
    return repo, benign_sha, attacker_sha


def resolve_action_ref(repo, ref):
    """Resolve the ref the way the runner uses it.

    A full commit SHA is the resolved object. Any other ref is looked up at
    use time, so a tag move between an earlier check and the download is
    visible. The lookup is git's ref resolution, which matched the SHA the
    hosted runner printed for vapier/coverity-scan-action@v1.
    """
    if SHA_RE.match(ref or ""):
        return ref
    for candidate in ("refs/tags/" + ref, "refs/heads/" + ref, ref):
        result = git(repo, "rev-parse", "--verify", "--end-of-options", candidate, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
    raise AssertionError("unresolved action ref %s" % ref)


def evaluate_expr(expr, inputs, github):
    expr = expr.strip()
    if expr.startswith("inputs."):
        return inputs.get(expr.split(".", 1)[1], "")
    if expr == "github.token":
        return github["token"]
    if expr.startswith("secrets."):
        return PLACEHOLDERS.get(secret_name(expr), "")
    return ""


def substitute(value, inputs, github):
    if not isinstance(value, str):
        return "" if value is None else str(value)

    def replace(match):
        return evaluate_expr(match.group(1), inputs, github)

    return EXPR_RE.sub(replace, value)


def workflow_inputs_for(step_info):
    """Map the workflow `with` block through the secrets context.

    system.github.token is not part of the secrets context; the job token is
    the github.token context value instead.
    """
    workflow = load_workflow(os.path.join(WORKFLOWS, step_info["file"]))
    job = workflow["jobs"][step_info["job"]]
    step = job["steps"][step_info["index"]]
    github = {"token": PLACEHOLDERS["GITHUB_TOKEN"]}
    inputs = {}
    for key, value in (step.get("with") or {}).items():
        inputs[str(key)] = substitute(value, inputs, github)
    # secrets.* expressions are evaluated while the step inputs are loaded,
    # before the composite action reads them.
    for key, value in list(inputs.items()):
        def replace(match, _inputs=inputs):
            expr = match.group(1).strip()
            if expr.startswith("secrets."):
                name = secret_name(expr)
                if name == "GITHUB_TOKEN":
                    return github["token"]
                return PLACEHOLDERS.get(name, "")
            return evaluate_expr(expr, _inputs, github)

        if isinstance(value, str):
            inputs[key] = EXPR_RE.sub(replace, value)
    return inputs, github


def run_resolved_action(repo, sha, inputs, github):
    """Run the composite action at sha, or return nothing if that object is not
    the moved tag's commit in this fixture.
    """
    listed = git(repo, "cat-file", "-t", sha, check=False)
    if listed.returncode != 0:
        return []
    manifest_bytes = git(repo, "show", "%s:action.yml" % sha).stdout
    manifest = yaml.safe_load(manifest_bytes)
    runs = (manifest or {}).get("runs") or {}
    if runs.get("using") != "composite":
        return []
    captured = []
    capture_path = os.path.join(repo, "captured.txt")
    for step in runs.get("steps") or []:
        env = os.environ.copy()
        env["CAPTURE_FILE"] = capture_path
        for key, value in (step.get("env") or {}).items():
            env[str(key)] = substitute(value, inputs, github)
        script = step.get("run")
        if not script:
            continue
        script = substitute(script, inputs, github)
        subprocess.run(
            ["bash", "-c", script],
            check=False,
            env=env,
            cwd=repo,
            capture_output=True,
            text=True,
        )
        if os.path.exists(capture_path):
            with open(capture_path, "r", encoding="utf-8") as handle:
                captured.extend(line for line in handle.read().splitlines() if line)
            os.remove(capture_path)
    return captured


def effective_permissions(workflow, job):
    """Job permissions replace the workflow permissions when the job sets them."""
    if isinstance(job, dict) and "permissions" in job:
        return job.get("permissions")
    return workflow.get("permissions")


class UnpinnedActionSecretTests(unittest.TestCase):
    def test_moved_tag_does_not_receive_step_secrets_or_job_token(self):
        steps = [
            step for step in iter_secret_actions()
            if step["job_runs_for_wolfssl"]
        ]
        self.assertTrue(steps, "expected at least the Coverity action step")
        coverity = [
            step for step in steps
            if step["file"] == "coverity-scan-fixes.yml"
            and step["name"] == "vapier/coverity-scan-action"
        ]
        self.assertEqual(len(coverity), 1)
        workflow = load_workflow(
            os.path.join(WORKFLOWS, "coverity-scan-fixes.yml")
        )
        triggers = workflow.get("on") or {}
        self.assertIn("schedule", triggers)
        job = workflow["jobs"]["coverity"]
        self.assertTrue(
            job_if_selects_owner(job, "wolfSSL"),
            "scheduled Coverity job is selected for repository owner wolfSSL",
        )
        self.assertFalse(
            job_if_selects_owner(job, "Goliath-Research"),
            "the same job is not selected for this fork's owner",
        )

        refs = [step["ref"] for step in steps if not SHA_RE.match(step["ref"])]
        # Always include the Coverity tag name so a pinned workflow is still
        # compared with a tag that an attacker can move.
        refs.append("v1")
        repo, benign_sha, attacker_sha = build_action_repo(refs)
        try:
            self.assertNotEqual(benign_sha, attacker_sha)
            self.assertEqual(resolve_action_ref(repo, "v1"), attacker_sha)
            # Resolve again after another move. A SHA pin must stay put.
            later = git(repo, "commit", "-q", "--allow-empty", "-m", "later move")
            self.assertEqual(later.returncode, 0)
            later_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
            git(repo, "tag", "-f", "v1", later_sha)
            self.assertEqual(resolve_action_ref(repo, "v1"), later_sha)
            self.assertNotEqual(resolve_action_ref(repo, benign_sha), later_sha)

            for step in steps:
                with self.subTest(uses=step["uses"], file=step["file"]):
                    resolved = resolve_action_ref(repo, step["ref"])
                    inputs, github = workflow_inputs_for(step)
                    captured = run_resolved_action(repo, resolved, inputs, github)
                    leaked = [
                        name for name, value in PLACEHOLDERS.items()
                        if value in captured
                    ]
                    self.assertNotIn(
                        resolved,
                        (attacker_sha, later_sha),
                        "%s:%s runs %s, which follows a movable ref" % (
                            step["file"], step["job"], step["uses"],
                        ),
                    )
                    self.assertEqual(
                        leaked,
                        [],
                        "%s passed secrets into the action selected by %s" % (
                            step["file"], step["uses"],
                        ),
                    )
        finally:
            shutil.rmtree(repo)

    def test_coverity_job_declares_read_only_token_permissions(self):
        workflow = load_workflow(
            os.path.join(WORKFLOWS, "coverity-scan-fixes.yml")
        )
        job = workflow["jobs"]["coverity"]
        permissions = effective_permissions(workflow, job)
        self.assertIsNotNone(
            permissions,
            "Coverity workflow does not set token permissions",
        )
        if isinstance(permissions, str):
            self.assertNotIn(permissions, ("write-all",))
            self.assertIn(permissions, ("read-all",))
            return
        self.assertIsInstance(permissions, dict)
        for scope, level in permissions.items():
            self.assertFalse(
                WRITE_RE.search(str(level)),
                "permission %s is %s" % (scope, level),
            )
        # An explicit permissions map sets every omitted scope to none.
        contents = permissions.get("contents", "none")
        self.assertIn(contents, ("read", "none"))


if __name__ == "__main__":
    unittest.main()
