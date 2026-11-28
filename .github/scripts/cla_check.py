# Copyright (C) 2026 Shirofune Security Co., Ltd.
#
# Unless explicitly acquired and licensed from Licensor under another license, the contents of this
# file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
# allowed by the RPL, and You may not copy or use this file in either source code or executable
# form, except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
# and limitations under the RPL.

"""Check PR authors against maintainer-verified CLA records on the trusted branch.

This checks recorded acceptance, not legal ownership or a signer's real identity.
It never signs for anyone or writes signature records. No PR code is executed.
"""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MARKER = "<!-- iwatobi-cla-required -->"
BOT_LOGIN = "github-actions[bot]"
ROOT = Path(__file__).resolve().parents[2]


class GateError(Exception):
    """An incomplete or invalid check must never produce a passing CLA status."""


def positive_id(value):
    return type(value) is int and value > 0


def email_digest(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def document_identity(root):
    raw = (root / "CLA.md").read_bytes()
    matches = re.findall(rb"^\*\*Version ([0-9]+(?:\.[0-9]+)+) [^\n]+\*\*$", raw, re.M)
    if len(matches) != 1:
        raise GateError("CLA.md has no unambiguous version heading")
    return matches[0].decode(), hashlib.sha256(raw).hexdigest()


def read_registry(data, version, digest):
    """Validate all records, then return accounts and aliases for this exact CLA."""
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1 or not isinstance(data.get("agreements"), list)):
        raise GateError("Invalid signature registry schema")
    accounts, aliases, records = {}, {}, set()
    for record in data["agreements"]:
        if not isinstance(record, dict):
            raise GateError("Invalid agreement record")
        allowed = {"record_id", "cla_version", "cla_sha256", "verified_at", "evidence_ref",
                   "verified_by_github_user_id", "github_user_ids", "github_logins",
                   "unlinked_author_email_sha256"}
        if set(record) - allowed:
            raise GateError("Unknown agreement fields; do not use unrecognized approval or revocation flags")
        for key in ("record_id", "cla_version", "cla_sha256", "verified_at", "evidence_ref"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise GateError(f"Agreement needs {key}")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", record["record_id"]):
            raise GateError("Invalid agreement record ID")
        if record["record_id"] in records:
            raise GateError("Duplicate agreement record ID")
        records.add(record["record_id"])
        if not re.fullmatch(r"[0-9a-f]{64}", record["cla_sha256"]):
            raise GateError("Agreement needs the full CLA SHA-256")
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", record["verified_at"]):
            raise GateError("Agreement needs a UTC verification timestamp")
        try:
            datetime.strptime(record["verified_at"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise GateError("Invalid verification date") from None
        if not positive_id(record.get("verified_by_github_user_id")):
            raise GateError("Agreement needs a reviewing maintainer's numeric GitHub ID")
        ids = record.get("github_user_ids")
        if not isinstance(ids, list) or not ids or not all(positive_id(i) for i in ids):
            raise GateError("Agreement needs covered numeric GitHub user IDs")
        if len(set(ids)) != len(ids):
            raise GateError("Duplicate covered account ID")
        logins = record.get("github_logins", {})
        if (not isinstance(logins, dict) or any(str(i) not in {str(uid) for uid in ids}
                or not isinstance(login, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?", login)
                for i, login in logins.items())):
            raise GateError("Invalid display login; numeric account IDs determine coverage")
        evidence = record["evidence_ref"]
        if not (re.fullmatch(r"private:[A-Za-z0-9._-]+", evidence)
                or re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/(?:issues|pull)/\d+#issuecomment-\d+", evidence)):
            raise GateError("Evidence must be a signature permalink or opaque private record ID")
        raw_aliases = record.get("unlinked_author_email_sha256", {})
        if not isinstance(raw_aliases, dict):
            raise GateError("Invalid unlinked-author map")
        for key, value in raw_aliases.items():
            if not re.fullmatch(r"[0-9a-f]{64}", key) or not positive_id(value) or value not in ids:
                raise GateError("Unlinked authors must map to an account covered by this agreement")
        if record["cla_version"] != version or record["cla_sha256"] != digest:
            continue
        for user_id in ids:
            accounts.setdefault(user_id, []).append(record["record_id"])
        for key, value in raw_aliases.items():
            if key in aliases and aliases[key] != value:
                raise GateError("Conflicting verified author identity")
            aliases[key] = value
    return accounts, aliases


def required_accounts(opener, commits, aliases, ignored_coauthors, ignored_coauthor_ids=frozenset()):
    """Include the PR opener, every primary author, and all human co-authors."""
    if not positive_id(opener.get("id")):
        raise GateError("Could not identify the PR opener")
    accounts = {opener["id"]: opener.get("login", str(opener["id"]))}
    unresolved = []

    def add(actor, commit_id, coauthor=False):
        if not isinstance(actor, dict):
            unresolved.append(f"Unknown author on {commit_id[:12]}")
            return
        email = str(actor.get("email") or "").strip().lower()
        user = actor.get("user") or {}
        # An AI service's synthetic trailer is not a rights holder. This never
        # exempts a primary author or PR opener, and does not allow whole domains.
        # GitHub may link the trailer's email to the AI service's own account, so
        # that exact account is skipped too, but only together with that email.
        linked_id = user.get("databaseId")
        if (coauthor and email in ignored_coauthors
                and (not positive_id(linked_id) or linked_id in ignored_coauthor_ids)):
            return
        user_id = user.get("databaseId")
        if not positive_id(user_id):
            user_id = aliases.get(email_digest(email)) if email else None
        if not positive_id(user_id):
            unresolved.append(f"Unlinked author on {commit_id[:12]}")
            return
        accounts[user_id] = user.get("login") or accounts.get(user_id, str(user_id))

    for commit in commits:
        commit_id = commit["oid"]
        primary = commit.get("author")
        add(primary, commit_id)
        authors = commit.get("authors") or {}
        nodes = authors.get("nodes") or []
        page_info = authors.get("pageInfo") or {}
        if (not isinstance(nodes, list) or not nodes or type(authors.get("totalCount")) is not int
                or authors["totalCount"] != len(nodes) or type(page_info.get("hasNextPage")) is not bool
                or page_info["hasNextPage"]):
            raise GateError("Incomplete co-author list; refusing to mark the CLA complete")
        primary_key = ((primary or {}).get("email"), ((primary or {}).get("user") or {}).get("databaseId"))
        if primary_key not in [((a or {}).get("email"), ((a or {}).get("user") or {}).get("databaseId")) for a in nodes]:
            raise GateError("Primary author is missing from the co-author response")
        for actor in nodes:
            key = ((actor or {}).get("email"), ((actor or {}).get("user") or {}).get("databaseId"))
            if key != primary_key:
                add(actor, commit_id, coauthor=True)
    return accounts, sorted(set(unresolved))


def assess(opener, commits, registry, ignored_coauthors, ignored_coauthor_ids=frozenset()):
    approved, aliases = registry
    required, unresolved = required_accounts(opener, commits, aliases, ignored_coauthors,
                                             ignored_coauthor_ids)
    missing = {user_id: login for user_id, login in required.items() if user_id not in approved}
    return {"ok": not missing and not unresolved, "missing": missing,
            "unresolved": unresolved, "required": required}


class GitHub:
    def __init__(self, token, dry_run=False):
        self.token, self.dry_run = token, dry_run

    def request(self, path, data=None, method=None):
        method = method or ("POST" if data is not None else "GET")
        query = str((data or {}).get("query", ""))
        is_query = path == "/graphql" and query.lstrip().startswith("query ") and not re.search(r"\bmutation\b", query)
        if self.dry_run and method != "GET" and not is_query:
            raise GateError("Dry-run mode prohibits GitHub writes")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "iwatobi-cla-check"}
        body = json.dumps(data).encode() if data is not None else None
        for attempt in range(3):
            try:
                with urlopen(Request("https://api.github.com" + path, body, headers, method=method), timeout=30) as response:
                    return json.load(response)
            except HTTPError as error:
                if error.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise GateError(f"GitHub API request failed (HTTP {error.code})") from None
            except (URLError, TimeoutError):
                raise GateError("GitHub API request did not complete") from None

    def pages(self, path):
        separator = "&" if "?" in path else "?"
        for page in range(1, 1001):
            data = self.request(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(data, list):
                raise GateError("Expected a paginated GitHub list")
            yield from data
            if len(data) < 100:
                return
        raise GateError("GitHub pagination limit exceeded")

    def commits(self, repo, number):
        owner, name = repo.split("/")
        query = """query ($owner:String!, $name:String!, $number:Int!, $after:String) {
          repository(owner:$owner, name:$name) { pullRequest(number:$number) {
            commits(first:100, after:$after) { pageInfo { hasNextPage endCursor }
              nodes { commit { oid author { email user { login databaseId } }
                authors(first:100) { totalCount pageInfo { hasNextPage }
                  nodes { email user { login databaseId } } } } }
            }
          } }
        }"""
        after = None
        seen = set()
        while True:
            result = self.request("/graphql", {"query": query, "variables": {
                "owner": owner, "name": name, "number": number, "after": after}})
            if result.get("errors"):
                raise GateError("Could not retrieve the complete commit author list")
            try:
                connection = result["data"]["repository"]["pullRequest"]["commits"]
                for node in connection["nodes"]:
                    yield node["commit"]
                info = connection["pageInfo"]
            except (TypeError, KeyError):
                raise GateError("Incomplete GitHub commit response") from None
            if not info["hasNextPage"]:
                return
            after = info["endCursor"]
            if not after or after in seen:
                raise GateError("Invalid GitHub commit pagination")
            seen.add(after)


def event_numbers(event_name, event, explicit_pr=None):
    if explicit_pr is not None:
        if not positive_id(explicit_pr):
            raise GateError("PR number must be a positive integer")
        return [explicit_pr]
    if event_name == "pull_request_target":
        if event.get("action") == "closed":
            return None
        return [event["pull_request"]["number"]]
    if event_name == "issue_comment":
        issue, comment = event.get("issue", {}), event.get("comment", {})
        text = str(comment.get("body", "")).strip()
        if (not issue.get("pull_request") or comment.get("user", {}).get("type") == "Bot"
                or not (text == "/cla recheck" or text.startswith("I have read the Iwatobi Contributor License Agreement,"))):
            return []
        return [issue["number"]]
    if event_name in ("push", "schedule", "workflow_dispatch"):
        return None  # Recheck every open PR, including PRs predating installation.
    return []


def notice(result, version, document_url, repo):
    if result["ok"]:
        return None
    missing = ", ".join(f"`@{login}` (ID {user_id})" for user_id, login in sorted(result["missing"].items()))
    text = f"{MARKER}\n### CLA {version}: verified acceptance needed\n\n"
    if missing:
        text += f"Missing current-version records for: {missing}.\n\n"
    if result["unresolved"]:
        text += "Some commit authors could not be linked to a GitHub account. Link the commit email to the account, or ask a maintainer to verify and register the identity.\n\n"
    text += (f"Please read the [CLA]({document_url}) and follow the [signing instructions]"
             f"(https://github.com/{repo}/blob/main/CONTRIBUTING.md#how-to-sign). "
             "If you already signed, a maintainer must verify and register the acceptance. "
             "After registration, later PRs can reuse it; this PR does not need reopening. "
             "Use the private signing process if identifying information must stay private.\n\n"
             "[Verified signer registry](https://github.com/" + repo + "/blob/main/.github/cla/signatures.json). "
             "This checks recorded acceptance; maintainers still review ownership, employer authority, and third-party licenses.\n\nby codex")
    return text


def check_pr(api, repo, number, registry, policy, version, document_url):
    pr = api.request(f"/repos/{repo}/pulls/{number}")
    if pr["state"] != "open":
        return {"pr": number, "skipped": "closed"}
    head = pr["head"]["sha"]
    if not api.dry_run:
        api.request(f"/repos/{repo}/statuses/{head}", {"state": "pending", "context": policy["status_context"],
                    "description": "Checking current CLA records and commit authors", "target_url": document_url})
    try:
        commits = list(api.commits(repo, number))
        if not commits or len(commits) != pr.get("commits") or len({c["oid"] for c in commits}) != len(commits):
            raise GateError("Incomplete or changing PR commit list; recheck required")
        result = assess(pr["user"], commits, registry,
                        set(policy["ignored_coauthor_emails"]),
                        set(policy.get("ignored_coauthor_account_ids", [])))
        # Commit statuses are shared by PRs with the same head SHA. Do not let
        # a signed opener's PR silently give an unsigned duplicate PR a green.
        for other in api.pages(f"/repos/{repo}/pulls?state=open"):
            if other.get("state") == "open" and other.get("head", {}).get("sha") == head:
                actor = other["user"]
                if not positive_id(actor.get("id")):
                    raise GateError("Unidentified PR opener for a shared head")
                result["required"][actor["id"]] = actor.get("login", str(actor["id"]))
                if actor["id"] not in registry[0]:
                    result["missing"][actor["id"]] = actor.get("login", str(actor["id"]))
        result["ok"] = not result["missing"] and not result["unresolved"]
    except GateError:
        if not api.dry_run:
            api.request(f"/repos/{repo}/statuses/{head}", {"state": "error", "context": policy["status_context"],
                        "description": "CLA check could not complete; recheck required", "target_url": document_url})
        raise
    # A synchronize event may race this run. Never attach this assessment to a
    # different revision; GitHub requires a new result on the new head.
    current = api.request(f"/repos/{repo}/pulls/{number}")
    if current["state"] != "open" or current["head"]["sha"] != head:
        return {"pr": number, "skipped": "head changed"}
    if not api.dry_run:
        api.request(f"/repos/{repo}/statuses/{head}", {
            "state": "success" if result["ok"] else "failure", "context": policy["status_context"],
            "description": f"CLA {version}: verified records cover listed authors" if result["ok"]
                           else f"CLA {version}: signature or maintainer verification needed",
            "target_url": document_url})
        body = notice(result, version, document_url, repo)
        if body:
            previous = next((c for c in api.pages(f"/repos/{repo}/issues/{number}/comments")
                             if c.get("user", {}).get("login") == BOT_LOGIN
                             and c.get("user", {}).get("type") == "Bot"
                             and str(c.get("body", "")).startswith(MARKER)), None)
            if previous and previous["body"] != body:
                api.request(f"/repos/{repo}/issues/comments/{previous['id']}", {"body": body}, method="PATCH")
            elif not previous:
                api.request(f"/repos/{repo}/issues/{number}/comments", {"body": body})
    return {"pr": number, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, help="Check one PR; otherwise use the workflow event")
    parser.add_argument("--all-open", action="store_true", help="Check all existing open PRs")
    parser.add_argument("--dry-run", action="store_true", help="Read GitHub only; never post comments or statuses")
    args = parser.parse_args()
    repo = os.environ.get("GITHUB_REPOSITORY", "Yamato-Security/iwatobi")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise GateError("Invalid repository name")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GateError("GITHUB_TOKEN is required")
    api = GitHub(token, args.dry_run)
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    numbers = None if args.all_open else event_numbers(os.environ.get("GITHUB_EVENT_NAME", ""), event, args.pr)
    if numbers is None:
        numbers = [pr["number"] for pr in api.pages(f"/repos/{repo}/pulls?state=open")]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    document_url = f"https://github.com/{repo}/blob/{commit}/CLA.md"
    try:
        version, digest = document_identity(ROOT)
        policy = json.loads((ROOT / ".github/cla/policy.json").read_text())
        if (type(policy.get("schema_version")) is not int or policy["schema_version"] != 1
                or policy.get("status_context") != "cla/required"):
            raise GateError("Invalid CLA policy")
        if (not isinstance(policy.get("ignored_coauthor_emails"), list)
                or not all(isinstance(x, str) and re.fullmatch(r"[^\s@*]+@[^\s@*]+", x) for x in policy["ignored_coauthor_emails"])):
            raise GateError("Ignored co-author metadata must use exact email addresses")
        ignored_ids = policy.get("ignored_coauthor_account_ids", [])
        if not isinstance(ignored_ids, list) or not all(positive_id(x) for x in ignored_ids):
            raise GateError("Ignored co-author accounts must be numeric GitHub account IDs")
        raw_registry = json.loads((ROOT / ".github/cla/signatures.json").read_text())
        registry = read_registry(raw_registry, version, digest)
    except (GateError, OSError, ValueError, TypeError, AttributeError) as error:
        # A bad trusted registry must replace an earlier green status, not just
        # fail this default-branch workflow while leaving the old result green.
        if not args.dry_run:
            for number in numbers:
                pr = api.request(f"/repos/{repo}/pulls/{number}")
                if pr["state"] == "open":
                    api.request(f"/repos/{repo}/statuses/{pr['head']['sha']}", {
                        "state": "error", "context": "cla/required", "target_url": document_url,
                        "description": "CLA policy/registry invalid; maintainer action required"})
        raise GateError(str(error)) from None
    results = []
    failed = False
    for number in numbers:
        try:
            results.append(check_pr(api, repo, number, registry, policy, version, document_url))
        except GateError:
            # One transient/bad PR response must not prevent the other existing
            # PRs from receiving their updated result.
            failed = True
            results.append({"pr": number, "error": "CLA check could not complete"})
    print(json.dumps({"version": version, "cla_sha256": digest, "dry_run": args.dry_run,
                      "verified_account_ids": sorted(registry[0]), "pull_requests": results}, indent=2))
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        lines = [f"## CLA {version}", "", f"Document SHA-256: `{digest}`", "",
                 f"[Verified signer list](https://github.com/{repo}/blob/main/.github/cla/signatures.json)", "",
                 "| GitHub account ID | Verified records |", "| --- | --- |"]
        display = {int(uid): login for r in raw_registry["agreements"]
                   if r["cla_version"] == version and r["cla_sha256"] == digest
                   for uid, login in r.get("github_logins", {}).items()}
        lines += [f"| {display.get(uid, '')} (ID {uid}) | {', '.join(ids)} |" for uid, ids in sorted(registry[0].items())]
        if not registry[0]:
            lines.append("| — | No verified signatures registered yet |")
        lines += ["", "| PR | Result |", "| --- | --- |"]
        lines += [f"| [#{r['pr']}](https://github.com/{repo}/pull/{r['pr']}) | "
                  f"{'Pass' if r.get('ok') else r.get('skipped', 'Signature/verification needed')} |" for r in results]
        Path(summary_path).write_text("\n".join(lines) + "\n")
    if failed:
        raise GateError("One or more PR checks could not complete; see their error statuses")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, KeyError, TypeError) as error:
        # Do not log request headers, tokens, signature text, or unlinked emails.
        print(f"CLA check failed: {error}", file=sys.stderr)
        sys.exit(1)
