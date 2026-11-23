#!/usr/bin/env python3
"""Membrowse actions that receive the API key must be pinned to a commit SHA.

These tests follow the actions runner's job-time resolution of a `uses:` ref
(actions/runner v2.338.2, ActionManager.GetDownloadInfoAsync and
ActionManifestManagerWrapper.ParseActionReference) and the way that runner
hands a composite action its inputs, step environment, and github.token
(StepsRunner, CompositeActionHandler, ExecutionContext, ScriptHandler).

A tag or branch is peeled to a commit when the job downloads the action, not
when the workflow file was written. Moving the tag between those moments
changes the code that runs with the API key and the job token. A 40-hex
commit SHA is not peeled through the tag.

The repository tests fail while a Membrowse step that can see the API key
still names a movable ref. They pass once every such reference is a full
commit SHA.

Run from the repository root:

    python3 tests/ci/test_membrowse_action_pin.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
OWNER_REPO = "membrowse/membrowse-action"

# Obvious placeholders. These are not credentials.
API_KEY = "placeholder-membrowse-api-key"
JOB_TOKEN = "placeholder-github-token"

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


class WorkflowLoader(yaml.SafeLoader):
    """Load workflow YAML without turning the key `on` into a boolean."""


def _strip_bool_resolver() -> None:
    for key, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
        WorkflowLoader.yaml_implicit_resolvers[key] = [
            (tag, regexp)
            for tag, regexp in resolvers
            if tag != "tag:yaml.org,2002:bool"
        ]


_strip_bool_resolver()


def load_workflow(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = yaml.load(handle, Loader=WorkflowLoader)
    if not isinstance(data, dict):
        raise AssertionError(f"{path} did not parse as a mapping")
    return data


def parse_action_reference(uses: str) -> tuple[str, str | None, str | None]:
    """Split uses the way ActionManifestManagerWrapper.ParseActionReference does.

    Returns (name, path, ref) for owner/repo@ref and owner/repo/path@ref.
    """
    at_index = uses.rfind("@")
    ref = None
    repo_part = uses
    if at_index > 0:
        ref = uses[at_index + 1 :]
        repo_part = uses[:at_index]
    parts = repo_part.split("/")
    if len(parts) >= 2:
        name = f"{parts[0]}/{parts[1]}"
        path = "/".join(parts[2:]) if len(parts) > 2 else None
    else:
        name = repo_part
        path = None
    return name, path or None, ref


def git(repo: Path, *args: str, check: bool = True) -> str:
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "pin-test")
    env.setdefault("GIT_AUTHOR_EMAIL", "pin-test@example.com")
    env.setdefault("GIT_COMMITTER_NAME", "pin-test")
    env.setdefault("GIT_COMMITTER_EMAIL", "pin-test@example.com")
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.stdout.strip()


def resolve_at_use(repo: Path, ref: str) -> str:
    """Resolve a uses ref the way a fresh runner job does.

    GetDownloadInfoAsync sends the ref string to the service when the job
    downloads the action. A full commit SHA is that object. Any other ref is
    peeled to the commit it names at that moment, which is what `git tag -f`
    changes. A full SHA is not looked up as a tag, so an earlier snapshot of
    the tag is not reused and a later move of the tag is not consulted.
    """
    if ref and SHA_RE.fullmatch(ref):
        return ref.lower()
    return git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")


def lookup(expr: str, scopes: dict) -> str:
    current = scopes
    for part in expr.split("."):
        if not isinstance(current, dict) or part not in current:
            return ""
        current = current[part]
    return "" if current is None else str(current)


def evaluate(value, scopes: dict):
    """Evaluate the `${{ }}` forms these workflows and the action use."""
    if not isinstance(value, str) or "${{" not in value:
        return value

    def replace(match: re.Match) -> str:
        expr = match.group(1).strip()
        for op in ("!=", "=="):
            if op in expr:
                left, right = (piece.strip() for piece in expr.split(op, 1))
                right = right.strip("'\"")
                actual = lookup(left, scopes)
                if op == "!=":
                    return "true" if actual != right else "false"
                return "true" if actual == right else "false"
        return lookup(expr, scopes)

    return EXPR_RE.sub(replace, value)


def condition_holds(step: dict, scopes: dict) -> bool:
    """StepsRunner merges step env before it evaluates the step `if`.

    Conditions that only mention the API-key env var are evaluated. Other
    conditions (artifact outputs, event filters) are treated as true so the
    download still happens on the job that reaches the action.
    """
    raw = step.get("if")
    if raw is None:
        return True
    text = str(raw)
    if "env.MEMBROWSE_API_KEY" in text:
        return evaluate(text, scopes) == "true"
    return True


class CommentSink(BaseHTTPRequestHandler):
    """Local stand-in for the pull-request comment endpoint.

    The action presents the job token. The sink accepts the comment only when
    that token is the job token and the job's permissions grant
    pull-requests: write. It records flags, never the token.
    """

    def do_POST(self) -> None:  # noqa: N802
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        server = self.server
        attempted = bool(token)
        accepted = attempted and token == server.job_token and server.permissions.get(
            "pull-requests"
        ) == "write"
        server.attempts.append(
            {"path": self.path, "attempted": attempted, "accepted": accepted}
        )
        self.send_response(201 if accepted else 403)
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:
        return


class ActionRepo:
    """Local action repository whose v1 tag can be moved onto another commit."""

    def __init__(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="membrowse-action-"))
        git(self.directory, "init", "-q")
        git(self.directory, "checkout", "-q", "-b", "main")
        self._write_tree(self._benign_manifest(), benign=True)
        git(self.directory, "add", "-A")
        git(self.directory, "commit", "-q", "-m", "benign action")
        self.benign_sha = git(self.directory, "rev-parse", "HEAD")
        git(self.directory, "tag", "v1")
        self._write_tree(self._malicious_manifest(), benign=False)
        git(self.directory, "add", "-A")
        git(self.directory, "commit", "-q", "-m", "replacement action")
        self.malicious_sha = git(self.directory, "rev-parse", "HEAD")
        # The tag still names the benign commit until the publisher moves it.
        self.assert_tag_at(self.benign_sha)

    def assert_tag_at(self, sha: str) -> None:
        current = git(self.directory, "rev-parse", "v1^{commit}")
        if current != sha:
            raise AssertionError(f"v1 is {current}, expected {sha}")

    def move_v1(self, sha: str) -> None:
        git(self.directory, "tag", "-f", "v1", sha)
        self.assert_tag_at(sha)

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)

    def _write_tree(self, manifest: str, benign: bool) -> None:
        script_text = _BENIGN_SCRIPT if benign else _MALICIOUS_SCRIPT
        for relative in (
            "action.yml",
            "comment-action/action.yml",
            "onboard-action/action.yml",
        ):
            path = self.directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(manifest, encoding="utf-8")
            (path.parent / "capture.py").write_text(script_text, encoding="utf-8")

    @staticmethod
    def _benign_manifest() -> str:
        return (
            "name: benign\n"
            "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - shell: bash\n"
            "      run: python3 \"${GITHUB_ACTION_PATH}/capture.py\"\n"
        )

    @staticmethod
    def _malicious_manifest() -> str:
        # Same channels the published composite action uses: an input copied
        # into INPUT_API_KEY, the caller step env, and github.token.
        return (
            "name: replacement\n"
            "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - shell: bash\n"
            "      env:\n"
            "        INPUT_API_KEY: ${{ inputs.api_key }}\n"
            "        MEMBROWSE_API_KEY: ${{ env.MEMBROWSE_API_KEY }}\n"
            "        GH_TOKEN: ${{ env.GH_TOKEN }}\n"
            "        GITHUB_TOKEN: ${{ github.token }}\n"
            "      run: python3 \"${GITHUB_ACTION_PATH}/capture.py\"\n"
        )


_BENIGN_SCRIPT = (
    "import json, os\n"
    "open(os.environ['RESULT_PATH'], 'w').write("
    "json.dumps({'benign': True, 'api_key_input': False, "
    "'api_key_env': False, 'gh_token_env': False, "
    "'github_token': False, 'comment_accepted': False}))\n"
)

_MALICIOUS_SCRIPT = r'''
import json
import os
import urllib.request

flags = {
    "benign": False,
    "api_key_input": bool(os.environ.get("INPUT_API_KEY")),
    "api_key_env": bool(os.environ.get("MEMBROWSE_API_KEY")),
    "gh_token_env": bool(os.environ.get("GH_TOKEN")),
    "github_token": bool(os.environ.get("GITHUB_TOKEN")),
    "comment_accepted": False,
}
token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
if token:
    request = urllib.request.Request(
        os.environ["COMMENT_URL"],
        data=b'{"body":"memory report"}',
        method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            flags["comment_accepted"] = response.status == 201
    except urllib.error.HTTPError as error:
        flags["comment_accepted"] = error.code == 201
with open(os.environ["RESULT_PATH"], "w", encoding="utf-8") as handle:
    json.dump(flags, handle)
'''


def job_permissions(workflow: dict, job: dict) -> dict[str, str]:
    """Job permissions replace workflow permissions when the job sets them."""
    chosen = job.get("permissions", workflow.get("permissions"))
    if chosen == "write-all":
        return {"contents": "write", "pull-requests": "write"}
    if chosen == "read-all":
        return {"contents": "read", "pull-requests": "read"}
    if isinstance(chosen, dict):
        return {str(key): str(value) for key, value in chosen.items()}
    return {}


def membrowse_steps():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = load_workflow(path)
        jobs = workflow.get("jobs") or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for index, step in enumerate(job.get("steps") or []):
                uses = step.get("uses") if isinstance(step, dict) else None
                if not isinstance(uses, str):
                    continue
                name, _path, _ref = parse_action_reference(uses)
                if name == OWNER_REPO:
                    yield path, workflow, job_name, job, index, step, uses


def run_uses(
    repo: ActionRepo,
    uses: str,
    step: dict,
    permissions: dict[str, str],
    sink: ThreadingHTTPServer,
    result_path: Path,
) -> dict:
    """Run one fresh job's download and composite execution for `uses`.

    The actions directory starts empty, matching a new ubuntu-24.04 runner
    process: the ref-named watermark in ActionManager is absent, so the job
    downloads whatever commit the ref names now.
    """
    name, action_path, ref = parse_action_reference(uses)
    if name != OWNER_REPO or not ref:
        raise AssertionError(uses)

    scopes = {
        "secrets": {"MEMBROWSE_API_KEY": API_KEY, "GITHUB_TOKEN": JOB_TOKEN},
        "github": {"token": JOB_TOKEN},
        "env": {},
        "inputs": {},
    }
    # StepsRunner evaluates the step env block, then the step if.
    step_env = {}
    for key, value in (step.get("env") or {}).items():
        step_env[str(key)] = str(evaluate(value, scopes))
    scopes["env"].update(step_env)
    if not condition_holds(step, scopes):
        return {
            "ran": False,
            "resolved": None,
            "api_key_input": False,
            "api_key_env": False,
            "gh_token_env": False,
            "github_token": False,
            "comment_accepted": False,
        }

    resolved = resolve_at_use(repo.directory, ref)
    if resolved != repo.malicious_sha:
        return {
            "ran": True,
            "resolved": resolved,
            "followed_moved_tag": False,
            "api_key_input": False,
            "api_key_env": False,
            "gh_token_env": False,
            "github_token": False,
            "comment_accepted": False,
        }

    inputs = {}
    for key, value in (step.get("with") or {}).items():
        inputs[str(key)] = str(evaluate(value, scopes))

    manifest_path = "action.yml" if not action_path else f"{action_path}/action.yml"
    manifest_text = git(repo.directory, "show", f"{resolved}:{manifest_path}")
    manifest = yaml.load(manifest_text, Loader=WorkflowLoader)
    embedded = (((manifest or {}).get("runs") or {}).get("steps")) or []

    # CompositeActionHandler copies inputs and github onto the embedded step,
    # then seeds its env from the global env plus the caller step's env
    # overrides, then evaluates the embedded step's own env block.
    child_scopes = {
        "inputs": inputs,
        "github": {"token": JOB_TOKEN},
        "env": dict(step_env),
        "secrets": scopes["secrets"],
    }
    child_env = dict(step_env)
    for embedded_step in embedded:
        for key, value in (embedded_step.get("env") or {}).items():
            child_env[str(key)] = str(evaluate(value, child_scopes))
        child_scopes["env"] = dict(child_env)

    sink.job_token = JOB_TOKEN
    sink.permissions = permissions
    sink.attempts = []
    if result_path.exists():
        result_path.unlink()

    checkout = Path(tempfile.mkdtemp(prefix="action-checkout-"))
    try:
        archive = subprocess.check_output(
            ["git", "-C", str(repo.directory), "archive", resolved]
        )
        subprocess.run(["tar", "-x", "-C", str(checkout)], input=archive, check=True)
        action_dir = checkout if not action_path else checkout / action_path
        process_env = os.environ.copy()
        process_env.update(child_env)
        process_env["RESULT_PATH"] = str(result_path)
        process_env["COMMENT_URL"] = sink.url
        process_env["GITHUB_ACTION_PATH"] = str(action_dir)
        script = embedded[0]["run"]
        subprocess.run(
            ["bash", "-c", script],
            cwd=action_dir,
            env=process_env,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        shutil.rmtree(checkout, ignore_errors=True)

    flags = json.loads(result_path.read_text(encoding="utf-8"))
    flags["ran"] = True
    flags["resolved"] = resolved
    flags["followed_moved_tag"] = True
    return flags


class MembrowseActionPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = ActionRepo()
        cls.repo.move_v1(cls.repo.malicious_sha)
        cls.result_path = Path(tempfile.mkdtemp(prefix="membrowse-result-")) / "flags.json"
        cls.sink = ThreadingHTTPServer(("127.0.0.1", 0), CommentSink)
        cls.sink.job_token = JOB_TOKEN
        cls.sink.permissions = {}
        cls.sink.attempts = []
        cls.sink.url = f"http://127.0.0.1:{cls.sink.server_address[1]}/comments"
        cls.thread = threading.Thread(target=cls.sink.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.sink.shutdown()
        cls.repo.cleanup()
        shutil.rmtree(cls.result_path.parent, ignore_errors=True)

    def test_parse_action_reference_splits_path_and_ref(self) -> None:
        name, path, ref = parse_action_reference(
            "membrowse/membrowse-action/comment-action@v1"
        )
        self.assertEqual(name, OWNER_REPO)
        self.assertEqual(path, "comment-action")
        self.assertEqual(ref, "v1")
        name, path, ref = parse_action_reference("membrowse/membrowse-action@v1")
        self.assertEqual(path, None)
        self.assertEqual(ref, "v1")

    def test_moving_the_tag_changes_the_commit_downloaded_at_use(self) -> None:
        repo = ActionRepo()
        try:
            self.assertEqual(resolve_at_use(repo.directory, "v1"), repo.benign_sha)
            snapshot = resolve_at_use(repo.directory, "v1")
            repo.move_v1(repo.malicious_sha)
            # A check that stored the old commit does not bind the later
            # download. The runner sends the ref again when the job runs.
            self.assertEqual(snapshot, repo.benign_sha)
            self.assertEqual(resolve_at_use(repo.directory, "v1"), repo.malicious_sha)
            self.assertNotEqual(
                resolve_at_use(repo.directory, repo.benign_sha), repo.malicious_sha
            )
        finally:
            repo.cleanup()

    def test_unpinned_ref_runs_the_replacement_with_the_key_and_token(self) -> None:
        flags = run_uses(
            self.repo,
            "membrowse/membrowse-action@v1",
            {
                "uses": "membrowse/membrowse-action@v1",
                "with": {"api_key": "${{ secrets.MEMBROWSE_API_KEY }}"},
            },
            {"contents": "read"},
            self.sink,
            self.result_path,
        )
        self.assertTrue(flags["followed_moved_tag"])
        self.assertTrue(flags["api_key_input"])
        self.assertTrue(flags["github_token"])
        self.assertFalse(flags["comment_accepted"])

        flags = run_uses(
            self.repo,
            "membrowse/membrowse-action/comment-action@v1",
            {
                "uses": "membrowse/membrowse-action/comment-action@v1",
                "if": "${{ env.MEMBROWSE_API_KEY != '' }}",
                "with": {"api_key": "${{ secrets.MEMBROWSE_API_KEY }}"},
                "env": {
                    "MEMBROWSE_API_KEY": "${{ secrets.MEMBROWSE_API_KEY }}",
                    "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
                },
            },
            {"contents": "read", "pull-requests": "write"},
            self.sink,
            self.result_path,
        )
        self.assertTrue(flags["api_key_input"])
        self.assertTrue(flags["api_key_env"])
        self.assertTrue(flags["gh_token_env"])
        self.assertTrue(flags["github_token"])
        self.assertTrue(flags["comment_accepted"])

    def test_sha_pin_keeps_running_the_commit_from_before_the_tag_moved(self) -> None:
        flags = run_uses(
            self.repo,
            f"membrowse/membrowse-action@{self.repo.benign_sha}",
            {
                "uses": f"membrowse/membrowse-action@{self.repo.benign_sha}",
                "with": {"api_key": "${{ secrets.MEMBROWSE_API_KEY }}"},
            },
            {"contents": "read", "pull-requests": "write"},
            self.sink,
            self.result_path,
        )
        self.assertFalse(flags["followed_moved_tag"])
        self.assertFalse(flags["api_key_input"])
        self.assertFalse(flags["comment_accepted"])
        self.assertEqual(flags["resolved"], self.repo.benign_sha)

    def test_repository_workflows_do_not_run_a_moved_membrowse_tag(self) -> None:
        found = list(membrowse_steps())
        self.assertGreaterEqual(len(found), 5)
        for path, workflow, job_name, job, _index, step, uses in found:
            _name, _action_path, ref = parse_action_reference(uses)
            with self.subTest(workflow=str(path.relative_to(ROOT)), job=job_name, uses=uses):
                flags = run_uses(
                    self.repo,
                    uses,
                    step,
                    job_permissions(workflow, job),
                    self.sink,
                    self.result_path,
                )
                exposed = any(
                    flags.get(name)
                    for name in (
                        "followed_moved_tag",
                        "api_key_input",
                        "api_key_env",
                        "gh_token_env",
                        "github_token",
                        "comment_accepted",
                    )
                )
                self.assertFalse(
                    exposed,
                    f"{path.relative_to(ROOT)} job {job_name} ref {ref!r} "
                    f"followed the moved tag at download and observed "
                    f"api_key_input={flags.get('api_key_input')} "
                    f"api_key_env={flags.get('api_key_env')} "
                    f"gh_token_env={flags.get('gh_token_env')} "
                    f"github_token={flags.get('github_token')} "
                    f"comment_accepted={flags.get('comment_accepted')}",
                )
                self.assertRegex(ref or "", r"^[0-9a-fA-F]{40}$")
                self.assertNotEqual(flags.get("resolved"), self.repo.malicious_sha)


if __name__ == "__main__":
    unittest.main(verbosity=2)
