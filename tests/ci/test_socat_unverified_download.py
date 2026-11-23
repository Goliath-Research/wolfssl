#!/usr/bin/env python3
"""Socat CI must not build a substituted source archive.

The socat workflow downloads a release tarball and then patches, configures,
and builds that tree. These tests publish a substitute archive on the host
named in the workflow (HTTP and HTTPS) and replay the job's shell steps the
way the GitHub Actions runner does.

They fail while a substituted archive is extracted or while any command from
that archive runs. They pass when every fetched body is authenticated before
it is extracted and before any of its build scripts run, including a second
fetch of the same URL after a check of the first body.

Run:

    python3 tests/ci/test_socat_unverified_download.py

The Run socat tests step is part of the replay, but the runner skips it when
an earlier step exits non-zero. This file does not start that step on its own.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "socat.yml"
MARKER = "CI_UNTRUSTED_ARCHIVE_MARKER"
OSP_REV = "e2f7fa41e8feb7a7e4a62df26075cc4fab537e89"
HOSTS_BEGIN = "# BEGIN socat-workflow-download-test\n"
HOSTS_END = "# END socat-workflow-download-test\n"
CA_NAME = "socat-workflow-download-test.crt"
# actions/runner v2.338.2 ScriptHandler uses bash with the sh argument
# format "-e {0}". The socat 1.8.0.0 job log prints the same shell line.
RUNNER_BASH = ("/usr/bin/bash", "-e")
STEP_TIMEOUT_S = 240
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def _sudo_write(path: str, data: bytes) -> None:
    _run(["sudo", "-n", "tee", path], input=data, stdout=subprocess.DEVNULL)


def _which(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise unittest.SkipTest(f"required program {name} is not installed")
    return found


class _ArchiveHandler(http.server.BaseHTTPRequestHandler):
    config = {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        if route == "/health":
            body = b"ok"
            self._send(200, body)
            return
        entry = self.config["routes"].get(route)
        if entry is None:
            self._send(404, b"not found")
            return
        count = entry["count"] = entry.get("count", 0) + 1
        bodies = entry["bodies"]
        chosen = bodies[min(count - 1, len(bodies) - 1)]
        body = Path(chosen).read_bytes()
        with open(self.config["log"], "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "path": route,
                        "count": count,
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "scheme": "https" if self.server.tls else "http",
                    }
                )
                + "\n"
            )
            handle.flush()
        self._send(200, body)

    def _send(self, status, body: bytes):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class _Server(http.server.ThreadingHTTPServer):
    def __init__(self, address, context):
        super().__init__(address, _ArchiveHandler)
        self.tls = context is not None
        self.context = context
        self.daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        if self.context is not None:
            sock = self.context.wrap_socket(sock, server_side=True)
        return sock, addr

    def handle_error(self, request, client_address):
        return


def _serve(config_path: str) -> None:
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    _ArchiveHandler.config = config
    for entry in config["routes"].values():
        entry["count"] = 0
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(config["cert"], config["key"])
    servers = (
        _Server(("0.0.0.0", 80), None),
        _Server(("0.0.0.0", 443), ctx),
    )
    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()


def _load_workflow():
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for name, job in document.get("jobs", {}).items():
        for step in job.get("steps") or []:
            run = step.get("run")
            if isinstance(run, str) and "socat-" in run and (
                "curl" in run or "wget" in run
            ):
                return name, job
    raise AssertionError(f"no socat download step in {WORKFLOW}")


def _versions(job) -> list[str]:
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    found = []
    for item in matrix.get("include") or []:
        if "socat_version" in item:
            found.append(str(item["socat_version"]))
    if not found and "socat_version" in matrix:
        found = [str(item) for item in matrix["socat_version"]]
    if not found:
        raise AssertionError("socat job matrix has no socat_version")
    return found


def _render(text: str, version: str, workspace: Path) -> str:
    def replace(match):
        expr = match.group(1).strip()
        if expr == "matrix.socat_version":
            return version
        if expr == "github.workspace":
            return str(workspace)
        raise AssertionError(f"workflow expression {expr!r} is not evaluated")

    return EXPR_RE.sub(replace, text)


def _run_steps(job):
    steps = []
    started = False
    for step in job.get("steps") or []:
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if not started and "socat-" in run and ("curl" in run or "wget" in run):
            started = True
        if started:
            steps.append(step)
    if not steps:
        raise AssertionError("socat download step was not selected")
    return steps


def _urls(text: str) -> list[urllib.parse.ParseResult]:
    found = []
    for raw in URL_RE.findall(text):
        raw = raw.rstrip(").,;")
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            found.append(parsed)
    return found


def _digest_is_pinned(digest: str) -> bool:
    if not digest:
        return False
    result = subprocess.run(
        ["git", "grep", "-I", "-F", "-q", "--untracked", digest],
        cwd=REPO,
        check=False,
    )
    return result.returncode == 0


def _craft_evil(official: Path, version: str, canary: Path, dest: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="socat-craft-") as tmp:
        root = Path(tmp)
        _run(["tar", "-xzf", str(official), "-C", str(root)])
        tree = root / f"socat-{version}"
        script = tree / "configure.ac"
        if not script.is_file():
            script = tree / "configure.in"
        if not script.is_file():
            raise AssertionError(f"{official} has no configure.ac or configure.in")
        # autoconf exposes m4 esyscmd to configure.ac. GNU m4 runs it via
        # /bin/sh -c while autoreconf generates configure, which is the build
        # step immediately after patch.
        line = (
            "esyscmd([/bin/sh -c 'printf executed > %s'])\n" % canary
        ).encode()
        script.write_bytes(line + script.read_bytes())
        (tree / MARKER).write_text("substituted archive\n", encoding="utf-8")
        _run(
            ["tar", "-czf", str(dest), "-C", str(root), f"socat-{version}"]
        )


def _openssl_certs(directory: Path, hosts: list[str]) -> tuple[Path, Path, Path]:
    openssl = _which("openssl")
    ca_key = directory / "ca.key"
    ca_crt = directory / "ca.crt"
    srv_key = directory / "srv.key"
    srv_csr = directory / "srv.csr"
    srv_crt = directory / "srv.crt"
    serial = directory / "ca.srl"
    _run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "1",
            "-subj", "/CN=socat-workflow-download-test",
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _run(
        [
            openssl, "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(srv_key), "-out", str(srv_csr),
            "-subj", "/CN=" + hosts[0],
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    san = "subjectAltName=" + ",".join(f"DNS:{host}" for host in hosts)
    ext = directory / "san.ext"
    ext.write_text(san + "\n", encoding="utf-8")
    _run(
        [
            openssl, "x509", "-req", "-in", str(srv_csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAserial", str(serial), "-CAcreateserial",
            "-out", str(srv_crt), "-days", "1",
            "-extfile", str(ext),
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return ca_crt, srv_crt, srv_key


def _install_ca(ca_crt: Path) -> None:
    target = Path("/usr/local/share/ca-certificates") / CA_NAME
    _sudo_write(str(target), ca_crt.read_bytes())
    _run(
        ["sudo", "-n", "update-ca-certificates"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _remove_ca() -> None:
    target = Path("/usr/local/share/ca-certificates") / CA_NAME
    subprocess.run(
        ["sudo", "-n", "rm", "-f", str(target)],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sudo", "-n", "update-ca-certificates", "--fresh"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _hijack_hosts(hosts: list[str]) -> bytes:
    original = Path("/etc/hosts").read_bytes()
    if HOSTS_BEGIN.encode() in original:
        raise AssertionError("/etc/hosts already contains the socat test block")
    block = HOSTS_BEGIN + "127.0.0.1 " + " ".join(hosts) + "\n" + HOSTS_END
    _sudo_write("/etc/hosts", original + block.encode())
    return original


def _restore_hosts(original: bytes | None) -> None:
    if original is None:
        return
    subprocess.run(
        ["sudo", "-n", "tee", "/etc/hosts"],
        input=original, stdout=subprocess.DEVNULL, check=False,
    )


def _wait_port(port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"archive server did not listen on port {port}")


def _clone_osp(dest: Path) -> None:
    _run(
        [
            "git", "clone", "--depth", "1",
            "https://github.com/wolfssl/osp.git", str(dest),
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", OSP_REV],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _run(
        ["git", "-C", str(dest), "checkout", "--detach", "FETCH_HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _replay_step(
    script: str, cwd: Path, workspace: Path, trace: Path, canary: Path
) -> int:
    if not cwd.is_dir():
        trace.write_text("working directory does not exist\n", encoding="utf-8")
        return 1
    script_path = workspace / ".runner-step.sh"
    script_path.write_text(script, encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C",
        "TMPDIR": "/tmp",
        "GITHUB_WORKSPACE": str(workspace),
    }
    proc = subprocess.Popen(
        [
            "strace", "-f", "-s", "200", "-o", str(trace),
            "-e", "trace=openat,creat,execve",
            *RUNNER_BASH, str(script_path),
        ],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.time() + STEP_TIMEOUT_S
    while proc.poll() is None and time.time() < deadline:
        # autoreconf runs the archive's esyscmd before configure finishes.
        # Stop once that command has written the canary.
        if canary.is_file():
            _kill_group(proc.pid)
            proc.wait(timeout=10)
            return proc.returncode if proc.returncode is not None else 1
        time.sleep(0.2)
    if proc.poll() is None:
        _kill_group(proc.pid)
        proc.wait(timeout=10)
        return 124
    return proc.returncode


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, 15)
    except ProcessLookupError:
        return
    try:
        time.sleep(0.5)
        os.killpg(pid, 9)
    except ProcessLookupError:
        return


class SocatUnverifiedDownloadTest(unittest.TestCase):
    def test_substituted_archive_is_not_extracted_or_executed(self):
        _which("curl")
        _which("tar")
        _which("patch")
        _which("autoreconf")
        _which("strace")
        _which("git")
        _which("sudo")
        job_name, job = _load_workflow()
        versions = _versions(job)
        steps = _run_steps(job)
        rendered = []
        for version in versions:
            rendered.append(
                (
                    version,
                    [
                        (
                            step.get("name", "run"),
                            _render(step["run"], version, Path("/workspace")),
                            step.get("working-directory"),
                        )
                        for step in steps
                    ],
                )
            )
        hosts = []
        for _version, step_list in rendered:
            for _name, script, _cwd in step_list:
                for url in _urls(script):
                    if url.hostname not in hosts:
                        hosts.append(url.hostname)
        if not hosts:
            self.fail(f"{job_name} run steps do not name an archive URL")

        original_hosts = None
        server = None
        try:
            with tempfile.TemporaryDirectory(prefix="socat-ci-") as tmp:
                root = Path(tmp)
                archives = self._prepare_archives(root, versions)
                ca_crt, srv_crt, srv_key = _openssl_certs(root, hosts)
                _install_ca(ca_crt)
                original_hosts = _hijack_hosts(hosts)
                log_path = root / "requests.log"
                routes = {}
                for version, paths in archives.items():
                    for rendered_version, step_list in rendered:
                        if rendered_version != version:
                            continue
                        for _name, script, _cwd in step_list:
                            for url in _urls(script):
                                if url.path in routes:
                                    continue
                                first = (
                                    paths["official"]
                                    if paths["pinned"]
                                    else paths["evil"]
                                )
                                routes[url.path] = {
                                    "bodies": [str(first), str(paths["evil"])],
                                    "count": 0,
                                }
                config = {
                    "cert": str(srv_crt),
                    "key": str(srv_key),
                    "log": str(log_path),
                    "routes": routes,
                }
                config_path = root / "server.json"
                config_path.write_text(json.dumps(config), encoding="utf-8")
                server = subprocess.Popen(
                    [
                        "sudo", "-n", sys.executable, str(Path(__file__).resolve()),
                        "--serve", str(config_path),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                _wait_port(80)
                _wait_port(443)
                self._probe(hosts)
                osp = root / "osp"
                _clone_osp(osp)
                failures = []
                for version in versions:
                    failures.extend(
                        self._exercise(root, osp, version, steps, log_path)
                    )
                if failures:
                    self.fail("\n".join(failures))
        finally:
            if server is not None and server.poll() is None:
                subprocess.run(
                    ["sudo", "-n", "kill", str(server.pid)],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    subprocess.run(
                        ["sudo", "-n", "kill", "-9", str(server.pid)],
                        check=False,
                    )
            _restore_hosts(original_hosts)
            _remove_ca()

    def _prepare_archives(self, root: Path, versions: list[str]) -> dict:
        prepared = {}
        # Render against a placeholder so the URL can be fetched before hosts
        # are redirected. The version is the only substitution in the URL.
        _name, job = _load_workflow()
        steps = _run_steps(job)
        for version in versions:
            script = _render(steps[0]["run"], version, root)
            urls = [url for url in _urls(script) if url.path.endswith(".tar.gz")]
            if not urls:
                urls = _urls(script)
            if not urls:
                raise AssertionError(f"no archive URL for socat {version}")
            official = root / f"official-{version}.tar.gz"
            _run(
                [
                    "curl", "-fsSL", "--retry", "3", "--retry-delay", "1",
                    "-o", str(official), urllib.parse.urlunparse(urls[0]),
                ]
            )
            digest = _sha256(official)
            canary = root / f"canary-{version}"
            evil = root / f"evil-{version}.tar.gz"
            _craft_evil(official, version, canary, evil)
            prepared[version] = {
                "official": official,
                "evil": evil,
                "canary": canary,
                "digest": digest,
                "pinned": _digest_is_pinned(digest),
                "evil_digest": _sha256(evil),
            }
        return prepared

    def _probe(self, hosts: list[str]) -> None:
        for host in hosts:
            for scheme in ("http", "https"):
                result = subprocess.run(
                    [
                        "curl", "-fsS", "--max-time", "5",
                        f"{scheme}://{host}/health",
                    ],
                    check=False, capture_output=True,
                )
                if result.returncode != 0 or result.stdout != b"ok":
                    raise AssertionError(
                        f"could not deliver a response from {scheme}://{host}"
                    )

    def _exercise(self, root, osp, version, steps, log_path) -> list[str]:
        workspace = root / f"work-{version}"
        workspace.mkdir()
        shutil.copytree(osp, workspace / "osp", symlinks=True)
        canary = root / f"canary-{version}"
        traces = []
        codes = []
        for index, step in enumerate(steps):
            script = _render(step["run"], version, workspace)
            relative = step.get("working-directory")
            if relative:
                cwd = workspace / _render(str(relative), version, workspace)
            else:
                cwd = workspace
            trace = workspace / f"trace-{index}.log"
            code = _replay_step(script, cwd, workspace, trace, canary)
            traces.append(trace.read_bytes() if trace.is_file() else b"")
            codes.append((step.get("name", "run"), code))
            if code != 0:
                break
        trace_blob = b"\n".join(traces)
        marker_hit = MARKER.encode() in trace_blob or any(
            workspace.rglob(MARKER)
        )
        executed = canary.is_file()
        requests = []
        if log_path.is_file():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                item = json.loads(line)
                if version in item["path"]:
                    requests.append(item)
        problems = []
        if not requests:
            problems.append(
                f"socat {version}: the download step never fetched an archive "
                "from the host the workflow names"
            )
        if marker_hit:
            problems.append(
                f"socat {version}: substituted archive was extracted "
                f"(marker {MARKER})"
            )
        if executed:
            problems.append(
                f"socat {version}: a command from the substituted archive ran "
                f"and wrote {canary}"
            )
        # A check of one response must not be followed by use of another fetch.
        if len(requests) >= 2 and requests[0]["sha256"] != requests[-1]["sha256"]:
            if marker_hit or executed:
                problems.append(
                    f"socat {version}: a later fetch of the archive was "
                    "extracted or executed after an earlier fetch"
                )
        if problems:
            detail = ", ".join(f"{name} exit {code}" for name, code in codes)
            return [f"{item} [{detail}]" for item in problems]
        return []


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--serve":
        _serve(sys.argv[2])
    else:
        unittest.main()
