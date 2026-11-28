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

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("cla_check", ROOT / ".github/scripts/cla_check.py")
cla = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cla)
VERSION, DIGEST = cla.document_identity(ROOT)
POLICY = {"status_context": "cla/required", "ignored_coauthor_emails": ["noreply@anthropic.com"],
          "ignored_coauthor_account_ids": [81847]}


def actor(user_id=10, email="a@example.org", login=None):
    return {"email": email, "user": {"databaseId": user_id, "login": login or f"user{user_id}"} if user_id else None}


def commit(primary=None, coauthors=(), oid="a" * 40):
    primary = primary or actor()
    nodes = [primary, *coauthors]
    return {"oid": oid, "author": primary, "authors": {
        "nodes": nodes, "totalCount": len(nodes), "pageInfo": {"hasNextPage": False}}}


def agreement(ids=(10,), **overrides):
    return {"record_id": "verified-test", "cla_version": VERSION, "cla_sha256": DIGEST,
            "github_user_ids": list(ids), "verified_by_github_user_id": 50,
            "verified_at": "2026-11-17T01:00:00Z", "evidence_ref": "private:test-record", **overrides}


def registry(*records):
    return cla.read_registry({"schema_version": 1, "agreements": list(records)}, VERSION, DIGEST)


class FakeGitHub:
    dry_run = False

    def __init__(self, commits=None):
        self.data = {"number": 7, "state": "open", "commits": 1,
                     "user": {"id": 10, "login": "user10"}, "head": {"sha": "f" * 40}}
        self.commit_list = [commit()] if commits is None else commits
        self.calls, self.comments, self.related = [], [], []
        self.changed = False

    def request(self, path, data=None, method=None):
        self.calls.append((path, data, method))
        if data is not None:
            return {"id": 99}
        result = copy.deepcopy(self.data)
        reads = sum(1 for _, d, _ in self.calls if d is None)
        if self.changed and reads > 1:
            result["head"]["sha"] = "e" * 40
        return result

    def commits(self, repo, number):
        yield from self.commit_list

    def pages(self, path):
        yield from self.comments if path.endswith("/comments") else self.related

    def states(self):
        return [data["state"] for _, data, _ in self.calls if data and "state" in data]


class RegistryTests(unittest.TestCase):
    def test_repository_registry_matches_the_document(self):
        data = json.loads((ROOT / ".github/cla/signatures.json").read_text())
        cla.read_registry(data, VERSION, DIGEST)

    def test_current_record_covers_ids(self):
        self.assertEqual(registry(agreement((10, 20)))[0], {10: ["verified-test"], 20: ["verified-test"]})

    def test_empty_registry_covers_nobody(self):
        self.assertEqual(registry(), ({}, {}))

    def test_old_version_does_not_count(self):
        self.assertEqual(registry(agreement(cla_version="0.9"))[0], {})

    def test_changed_document_same_version_does_not_count(self):
        self.assertEqual(registry(agreement(cla_sha256="0" * 64))[0], {})

    def test_another_repository_signature_does_not_count(self):
        other_document = (ROOT / 'CLA.md').read_text().replace(
            'Yamato-Security/iwatobi', 'Yamato-Security/juntei')
        other_digest = cla.hashlib.sha256(other_document.encode()).hexdigest()
        self.assertNotEqual(other_digest, DIGEST)
        self.assertEqual(registry(agreement(cla_sha256=other_digest))[0], {})

    def test_ruleset_requires_cla_from_github_actions_without_bypass(self):
        rule = json.loads((ROOT / '.github/cla/ruleset.json').read_text())
        self.assertEqual(rule['enforcement'], 'active')
        self.assertEqual(rule['bypass_actors'], [])
        self.assertEqual(rule['conditions']['ref_name']['include'], ['~DEFAULT_BRANCH'])
        rules = {entry['type']: entry for entry in rule['rules']}
        self.assertIn('pull_request', rules)
        checks = rules['required_status_checks']['parameters']
        self.assertIs(checks['strict_required_status_checks_policy'], True)
        self.assertEqual(checks['required_status_checks'], [
            {'context': 'cla/required', 'integration_id': 15368}])

    def test_alias_must_be_covered_and_unambiguous(self):
        key = cla.email_digest("old@example.org")
        self.assertEqual(registry(agreement(unlinked_author_email_sha256={key: 10}))[1], {key: 10})
        with self.assertRaises(cla.GateError):
            registry(agreement(unlinked_author_email_sha256={key: 20}))
        with self.assertRaises(cla.GateError):
            registry(agreement(unlinked_author_email_sha256={key: 10}), agreement(
                (20,), record_id="second", unlinked_author_email_sha256={key: 20}))

    def test_old_alias_does_not_count(self):
        self.assertEqual(registry(agreement(cla_version="0.9", unlinked_author_email_sha256={"a" * 64: 10}))[1], {})

    def test_bad_records_fail_closed(self):
        cases = [agreement(github_user_ids=[True]), agreement(github_user_ids=[]),
                 agreement(github_user_ids=[10, 10]), agreement(verified_by_github_user_id=0),
                 agreement(verified_at="2026-02-31T00:00:00Z"), agreement(cla_sha256="short"),
                 agreement(evidence_ref="https://evil.example/signature"),
                 agreement(approved=False), agreement(github_logins={"20": "someone"}),
                 agreement(github_logins={"10": "<script>"})]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(cla.GateError):
                registry(data)

    def test_duplicate_records_are_rejected(self):
        with self.assertRaises(cla.GateError):
            registry(agreement(), agreement())

    def test_boolean_schema_is_rejected(self):
        with self.assertRaises(cla.GateError):
            cla.read_registry({"schema_version": True, "agreements": []}, VERSION, DIGEST)

    def test_display_login_never_changes_numeric_identity(self):
        approved = registry(agreement(github_logins={"10": "renamed-account"}))[0]
        self.assertIn(10, approved)
        self.assertNotIn("renamed-account", approved)


class AuthorTests(unittest.TestCase):
    def check(self, commits=None, records=(), opener=None):
        return cla.assess(opener or {"id": 10, "login": "user10"}, commits or [commit()],
                          registry(*records), set(POLICY["ignored_coauthor_emails"]),
                          set(POLICY["ignored_coauthor_account_ids"]))

    def test_signed_author_passes(self):
        self.assertTrue(self.check(records=[agreement()])["ok"])

    def test_unsigned_opener_is_required_even_with_signed_commits(self):
        result = self.check(records=[agreement()], opener={"id": 20, "login": "user20"})
        self.assertEqual(result["missing"], {20: "user20"})

    def test_each_commit_author_is_required(self):
        result = self.check([commit(), commit(actor(20), oid="b" * 40)], [agreement()])
        self.assertIn(20, result["missing"])

    def test_coauthor_is_required(self):
        result = self.check([commit(coauthors=[actor(20)])], [agreement()])
        self.assertIn(20, result["missing"])

    def test_synthetic_trailer_does_not_exempt_primary_or_opener(self):
        ai = actor(None, "noreply@anthropic.com")
        self.assertTrue(self.check([commit(coauthors=[ai])], [agreement()])["ok"])
        self.assertFalse(self.check([commit(ai)], [agreement()])["ok"])
        self.assertFalse(self.check([commit(coauthors=[ai])])["ok"])

    def test_identified_account_is_not_exempted_by_synthetic_email(self):
        result = self.check([commit(coauthors=[actor(20, "noreply@anthropic.com")])], [agreement()])
        self.assertIn(20, result["missing"])

    def test_ai_service_account_linked_to_trailer_is_skipped_only_as_coauthor(self):
        ai = actor(81847, "noreply@anthropic.com", "claude")
        self.assertTrue(self.check([commit(coauthors=[ai])], [agreement()])["ok"])
        self.assertFalse(self.check([commit(ai)], [agreement()])["ok"])
        self.assertFalse(self.check([commit(coauthors=[ai])])["ok"])
        result = self.check([commit(coauthors=[ai])], [agreement()], opener={"id": 81847, "login": "claude"})
        self.assertEqual(result["missing"], {81847: "claude"})

    def test_ai_service_account_needs_the_trailer_email(self):
        result = self.check([commit(coauthors=[actor(81847, "person@example.org", "claude")])], [agreement()])
        self.assertEqual(result["missing"], {81847: "claude"})

    def test_unknown_authors_fail_even_if_every_known_user_signed(self):
        result = self.check([commit(coauthors=[actor(None)])], [agreement()])
        self.assertFalse(result["ok"])
        self.assertTrue(result["unresolved"])

    def test_verified_alias_resolves_only_unlinked_authors(self):
        record = agreement(unlinked_author_email_sha256={cla.email_digest("old@example.org"): 10})
        self.assertTrue(self.check([commit(actor(None, "old@example.org"))], [record])["ok"])
        result = self.check([commit(actor(20, "old@example.org"))], [record])
        self.assertIn(20, result["missing"])

    def test_corporate_record_can_cover_multiple_listed_accounts(self):
        self.assertTrue(self.check([commit(coauthors=[actor(20)])], [agreement((10, 20))])["ok"])

    def test_incomplete_coauthor_page_fails_closed(self):
        data = commit()
        for change in [{"totalCount": 2}, {"pageInfo": {"hasNextPage": True}}]:
            candidate = copy.deepcopy(data)
            candidate["authors"].update(change)
            with self.subTest(change=change), self.assertRaises(cla.GateError):
                self.check([candidate], [agreement()])

    def test_missing_author_connection_is_not_a_pass(self):
        data = commit()
        data.pop("authors")
        with self.assertRaises(cla.GateError):
            self.check([data], [agreement()])

    def test_missing_page_info_or_primary_is_not_a_pass(self):
        data = commit()
        data["authors"].pop("pageInfo")
        with self.assertRaises(cla.GateError):
            self.check([data], [agreement()])
        data = commit()
        data["authors"]["nodes"] = [actor(20)]
        with self.assertRaises(cla.GateError):
            self.check([data], [agreement((10, 20))])


class ApiAndEventTests(unittest.TestCase):
    def test_dry_run_cannot_write_or_execute_mutations(self):
        api = cla.GitHub("do-not-print", dry_run=True)
        for path, data in [("/repos/test/statuses/a", {"state": "success"}),
                           ("/graphql", {"query": "mutation { deleteIssue }"}),
                           ("/graphql", {"query": "query { viewer { login } } mutation { deleteIssue }"})]:
            with self.subTest(path=path), self.assertRaises(cla.GateError):
                api.request(path, data)

    def test_graphql_commit_pages_are_all_read(self):
        api = cla.GitHub("fake", dry_run=True)
        def response(nodes, has_next, cursor):
            return {"data": {"repository": {"pullRequest": {"commits": {
                "nodes": [{"commit": c} for c in nodes],
                "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}}}}}}
        with patch.object(api, "request", side_effect=[response([commit()], True, "next"),
                                                      response([commit(oid="b" * 40)], False, None)]) as request:
            self.assertEqual(len(list(api.commits("owner/repo", 1))), 2)
            self.assertEqual(request.call_args_list[1].args[1]["variables"]["after"], "next")

    def test_graphql_errors_are_not_partial_success(self):
        api = cla.GitHub("fake")
        with patch.object(api, "request", return_value={"errors": [{"message": "failed"}]}):
            with self.assertRaises(cla.GateError):
                list(api.commits("owner/repo", 1))

    def test_normal_issue_and_bot_comments_do_not_trigger_checks(self):
        self.assertEqual(cla.event_numbers("issue_comment", {"issue": {"number": 1},
            "comment": {"body": "/cla recheck"}}), [])
        self.assertEqual(cla.event_numbers("issue_comment", {"issue": {"number": 1, "pull_request": {}},
            "comment": {"body": "/cla recheck", "user": {"type": "Bot"}}}), [])

    def test_signature_and_recheck_comment_keep_existing_pr(self):
        for body in ["/cla recheck", "I have read the Iwatobi Contributor License Agreement, version 1.1,"]:
            event = {"issue": {"number": 17, "pull_request": {"url": "example"}},
                     "comment": {"body": body, "user": {"type": "User"}}}
            self.assertEqual(cla.event_numbers("issue_comment", event), [17])

    def test_backfill_and_closed_events_scan_open_prs(self):
        for event in ["push", "schedule", "workflow_dispatch"]:
            self.assertIsNone(cla.event_numbers(event, {}))
        self.assertIsNone(cla.event_numbers("pull_request_target", {"action": "closed"}))

    def test_invalid_explicit_pr_is_rejected(self):
        for value in [-1, 0, True]:
            with self.assertRaises(cla.GateError):
                cla.event_numbers("workflow_dispatch", {}, value)

    def test_ambiguous_document_heading_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "CLA.md").write_text("**Version 1.1 — Date**\n**Version 1.1 — Other**\n")
            with self.assertRaises(cla.GateError):
                cla.document_identity(root)


class WorkflowResultTests(unittest.TestCase):
    def test_privileged_workflow_checks_out_only_default_branch(self):
        workflow = (ROOT / ".github/workflows/cla.yml").read_text()
        privileged = workflow.split("  enforce:", 1)[1]
        self.assertIn('ref: ${{ github.event.repository.default_branch }}', privileged)
        self.assertIn('persist-credentials: false', privileged)
        self.assertNotIn('pull_request.head', privileged)
        self.assertNotIn('contents: write', privileged)
        self.assertIn('CLA_REQUESTED_PR: ${{ inputs.pull_request }}', privileged)
        self.assertIn('--pr "$CLA_REQUESTED_PR"', privileged)

    def test_bad_registry_marks_all_existing_prs_error(self):
        api = FakeGitHub()
        api.related = [{"number": 7}, {"number": 8}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/cla").mkdir(parents=True)
            (root / "CLA.md").write_bytes((ROOT / "CLA.md").read_bytes())
            (root / ".github/cla/policy.json").write_text(json.dumps({"schema_version": 1, **POLICY}))
            (root / ".github/cla/signatures.json").write_text('{"schema_version":0,"agreements":[]}')
            with patch.object(cla, "ROOT", root), patch.object(cla, "GitHub", return_value=api), \
                 patch.object(cla.subprocess, "check_output", return_value="f" * 40), \
                 patch.object(cla.sys, "argv", ["cla_check.py", "--all-open"]), \
                 patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "GITHUB_REPOSITORY": "owner/repo", "GITHUB_EVENT_PATH": ""}):
                with self.assertRaises(cla.GateError):
                    cla.main()
        self.assertEqual(api.states(), ["error", "error"])

    def test_bad_ignored_account_ids_fail_closed(self):
        for bad in (["81847"], [True], [0], 81847):
            api = FakeGitHub()
            api.related = [{"number": 7}]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".github/cla").mkdir(parents=True)
                (root / "CLA.md").write_bytes((ROOT / "CLA.md").read_bytes())
                policy = {"schema_version": 1, **POLICY, "ignored_coauthor_account_ids": bad}
                (root / ".github/cla/policy.json").write_text(json.dumps(policy))
                (root / ".github/cla/signatures.json").write_text('{"schema_version":1,"agreements":[]}')
                with patch.object(cla, "ROOT", root), patch.object(cla, "GitHub", return_value=api), \
                     patch.object(cla.subprocess, "check_output", return_value="f" * 40), \
                     patch.object(cla.sys, "argv", ["cla_check.py", "--all-open"]), \
                     patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "GITHUB_REPOSITORY": "owner/repo", "GITHUB_EVENT_PATH": ""}):
                    with self.assertRaises(cla.GateError):
                        cla.main()
            self.assertEqual(api.states(), ["error"])

    def check(self, api, records=()):
        return cla.check_pr(api, "owner/repo", 7, registry(*records), POLICY, VERSION, "https://example.org/cla")

    def test_pass_publishes_pending_then_success(self):
        api = FakeGitHub()
        self.assertTrue(self.check(api, [agreement()])["ok"])
        self.assertEqual(api.states(), ["pending", "success"])

    def test_failure_posts_one_instruction_comment(self):
        api = FakeGitHub()
        self.assertFalse(self.check(api)["ok"])
        self.assertEqual(api.states(), ["pending", "failure"])
        bodies = [d["body"] for _, d, _ in api.calls if d and "body" in d]
        self.assertEqual(len(bodies), 1)
        self.assertTrue(bodies[0].endswith("by codex"))

    def test_partial_commit_results_replace_success_with_error(self):
        api = FakeGitHub(commits=[])
        with self.assertRaises(cla.GateError):
            self.check(api, [agreement()])
        self.assertEqual(api.states(), ["pending", "error"])

    def test_duplicate_commit_page_is_rejected(self):
        api = FakeGitHub(commits=[commit(), commit()])
        api.data["commits"] = 2
        with self.assertRaises(cla.GateError):
            self.check(api, [agreement()])

    def test_head_race_never_marks_new_head_successful(self):
        api = FakeGitHub()
        api.changed = True
        self.assertEqual(self.check(api, [agreement()])["skipped"], "head changed")
        self.assertEqual(api.states(), ["pending"])

    def test_signed_duplicate_head_does_not_cover_unsigned_opener(self):
        api = FakeGitHub()
        api.related = [{"state": "open", "head": api.data["head"], "user": {"id": 20, "login": "user20"}}]
        result = self.check(api, [agreement()])
        self.assertIn(20, result["missing"])
        self.assertEqual(api.states(), ["pending", "failure"])

    def test_external_comment_cannot_impersonate_bot(self):
        api = FakeGitHub()
        api.comments = [{"id": 8, "body": cla.MARKER + " pretend bot", "user": {"login": "someone", "type": "User"}}]
        self.check(api)
        self.assertFalse(any(method == "PATCH" for _, _, method in api.calls))

    def test_existing_bot_comment_is_updated_instead_of_spammed(self):
        api = FakeGitHub()
        api.comments = [{"id": 8, "body": cla.MARKER + " old", "user": {"login": cla.BOT_LOGIN, "type": "Bot"}}]
        self.check(api)
        self.assertTrue(any(method == "PATCH" for _, _, method in api.calls))

    def test_dry_run_emits_no_writes(self):
        api = FakeGitHub()
        api.dry_run = True
        self.check(api)
        self.assertTrue(all(data is None for _, data, _ in api.calls))


if __name__ == "__main__":
    unittest.main()
