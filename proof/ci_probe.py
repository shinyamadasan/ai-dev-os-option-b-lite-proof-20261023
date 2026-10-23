"""Synthetic GitHub authorization probe. Never prints authentication material."""
import json
import os
import sys
import urllib.error
import urllib.request

REPO = "shinyamadasan/ai-dev-os-option-b-lite-proof-20261023"
if os.environ.get("GITHUB_REPOSITORY") != REPO:
    raise SystemExit("Refusing any repository except the disposable proof repository")

def request(method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + path,
        data=body, method=method,
        headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)

try:
    status, head = request("GET", "/git/ref/heads/main")
    if status != 200:
        print(json.dumps({"result": "UNVERIFIED", "positive_read_http": status}))
        raise SystemExit(2)
    branch = "ci-unauthorized-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    status, response = request("POST", "/git/refs",
        {"ref": "refs/heads/" + branch, "sha": head["object"]["sha"]})
    result = "PASS" if status == 403 and response.get("message") == "Resource not accessible by integration" else "FAIL" if status == 201 else "UNVERIFIED"
    print(json.dumps({"result": result, "positive_read_http": 200,
        "write_http": status, "test_branch": branch,
        "message": response.get("message", ""),
        "credential": "job-scoped GITHUB_TOKEN, contents:read"}))
    raise SystemExit(0 if result == "PASS" else 1 if result == "FAIL" else 2)
except (urllib.error.URLError, TimeoutError):
    print(json.dumps({"result": "UNVERIFIED", "reason": "network/environment failure"}))
    raise SystemExit(2)
