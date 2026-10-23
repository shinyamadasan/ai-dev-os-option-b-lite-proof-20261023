"""Disposable-only SSH actor tests. The private key never leaves this runner."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = "shinyamadasan/ai-dev-os-option-b-lite-proof-20261023"
assert os.environ.get("GITHUB_REPOSITORY") == REPO
ROOT = Path.cwd() / ".proof-runtime"
KEY = ROOT / "id"
HOSTS = ROOT / "known_hosts"
REMOTE = "git@github.com:" + REPO + ".git"
RUN = os.environ["GITHUB_RUN_ID"]
BRANCH = "proof/ssh-publish-" + RUN
RESULTS = []

def emit(test, result, **fields):
    row = {"test": test, "result": result, **fields}
    RESULTS.append(row)
    print(json.dumps(row), flush=True)

def api(path):
    request = urllib.request.Request("https://api.github.com/repos/" + REPO + path,
        headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)

def command(args, cwd=None):
    # No inherited GH/GITHUB token, credential helper, SSH agent or owner HOME.
    env = {"PATH": os.environ["PATH"], "HOME": str(ROOT / "home"),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": SSH}
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=60)

def git(args, cwd):
    return command(["git", "-c", "credential.helper=", *args], cwd)

def require_success(run):
    if run.returncode:
        raise RuntimeError("Git/SSH command failed: " + run.stderr[-1200:])
    return run.stdout.strip()

def denied_push(test, run):
    diagnostic = run.stdout + run.stderr
    if run.returncode == 0:
        emit(test, "FAIL", reason="Unexpected successful unauthorized update; STOP path",
             diagnostic=diagnostic[-1600:])
        raise SystemExit(1)
    if "GH006" in diagnostic or "GH013" in diagnostic or "protected branch" in diagnostic:
        emit(test, "PASS", reason="GitHub protected-ref authorization refusal",
             diagnostic=diagnostic[-1600:])
    else:
        emit(test, "UNVERIFIED", reason="No valid GitHub protection refusal",
             diagnostic=diagnostic[-1600:])
        raise SystemExit(2)

SSH = " ".join(shlex.quote(a) for a in ["ssh", "-F", "/dev/null", "-i", str(KEY),
    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(HOSTS)])

if sys.argv[1] == "prepare":
    ROOT.mkdir(mode=0o700)
    (ROOT / "home").mkdir(mode=0o700)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "disposable-proof-" + RUN, "-f", str(KEY)], check=True)
    # Public GitHub Ed25519 host key from official fingerprint documentation.
    HOSTS.write_text("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n")
    emit("key_preparation", "PASS", private_key_exported=False,
         public_artifact="ssh-proof-public-key", feature_branch=BRANCH)
    raise SystemExit(0)

try:
    auth = None
    for _ in range(45):
        auth = command(shlex.split(SSH) + ["-T", "git@github.com"])
        if ("Hi " + REPO + "!") in auth.stdout + auth.stderr:
            break
        time.sleep(15)
    else:
        emit("deploy_key_authentication", "UNVERIFIED", reason="Registration/authentication not established")
        raise SystemExit(2)
    emit("deploy_key_authentication", "PASS", actor=REPO, owner_personal_key_used=False)
    subject = ROOT / "subject"
    require_success(git(["clone", REMOTE, str(subject)], ROOT))
    base = require_success(git(["rev-parse", "origin/main"], subject))
    require_success(git(["switch", "-c", BRANCH, "origin/main"], subject))
    (subject / "ssh-marker.txt").write_text("Synthetic SSH actor " + RUN + "\n")
    require_success(git(["add", "--", "ssh-marker.txt"], subject))
    require_success(git(["-c", "user.name=SSH proof", "-c", "user.email=ssh-proof@example.invalid",
                         "commit", "-m", "test: isolated SSH publishing actor"], subject))
    head = require_success(git(["rev-parse", "HEAD"], subject))
    pushed = git(["-c", "push.followTags=false", "push", "origin", "HEAD:refs/heads/" + BRANCH], subject)
    require_success(pushed)
    emit("ssh_feature_publish", "PASS", head=head, base=base, branch=BRANCH)
    denied_push("ssh_direct_main_without_pr",
        git(["push", "origin", "HEAD:refs/heads/main"], subject))
    denied_push("ssh_explicit_owner_update_rule",
        git(["push", "origin", "HEAD:refs/heads/policy-probe"], subject))
    # Public/controller-created PR is setup only; no PR-only token claim here.
    for _ in range(45):
        prs = api("/pulls?state=open&head=shinyamadasan:" + BRANCH)
        if prs:
            pr = api("/pulls/" + str(prs[0]["number"]))
            checks = api("/commits/" + head + "/check-runs")["check_runs"]
            required = [c for c in checks if c["name"] in ("proof", "readonly-token-negative")]
            if required and all(c["conclusion"] == "success" for c in required) and pr.get("mergeable_state") == "clean":
                break
        time.sleep(10)
    else:
        emit("ssh_local_green_pr_merge", "UNVERIFIED", reason="No clean green synthetic PR before deadline")
        raise SystemExit(2)
    require_success(git(["fetch", "origin", "refs/pull/" + str(pr["number"]) + "/merge"], subject))
    merge = require_success(git(["rev-parse", "FETCH_HEAD"], subject))
    parents = require_success(git(["show", "-s", "--format=%P", merge], subject)).split()
    if parents != [base, head]:
        emit("green_pr_precondition", "UNVERIFIED", reason="Merge/base/head identity moved")
        raise SystemExit(2)
    # Head checks are insufficient: protected-ref updates evaluate the actual pushed SHA.
    # Publish the merge object to an ordinary synthetic branch and test that exact object.
    merge_branch = "proof/ssh-merge-candidate-" + RUN
    require_success(git(["push", "origin", merge + ":refs/heads/" + merge_branch], subject))
    for _ in range(45):
        checks = api("/commits/" + merge + "/check-runs")["check_runs"]
        required = [c for c in checks if c["name"] in ("proof", "readonly-token-negative")]
        if {c["name"] for c in required} == {"proof", "readonly-token-negative"} and all(c["status"] == "completed" and c["conclusion"] == "success" for c in required):
            break
        time.sleep(10)
    else:
        emit("green_pr_precondition", "UNVERIFIED", reason="Exact pushed merge SHA lacks successful required checks")
        raise SystemExit(2)
    if api("/git/ref/heads/main")["object"]["sha"] != base:
        emit("green_pr_precondition", "UNVERIFIED", reason="Main identity moved")
        raise SystemExit(2)
    emit("green_pr_precondition", "PASS", pr=pr["number"], head=head, test_merge=merge,
         exact_merge_checks=[{"name": c["name"], "id": c["id"], "conclusion": c["conclusion"]} for c in required])
    denied_push("ssh_local_green_pr_merge",
        git(["push", "origin", merge + ":refs/heads/main"], subject))
except (urllib.error.URLError, TimeoutError, subprocess.TimeoutExpired):
    emit("environment", "UNVERIFIED", reason="Network or process timeout; not an authorization denial")
    raise SystemExit(2)
except RuntimeError as error:
    emit("environment", "UNVERIFIED", reason=str(error))
    raise SystemExit(2)
finally:
    # Safe evidence only. Neither private key nor environment values are artifacts.
    (ROOT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n")
