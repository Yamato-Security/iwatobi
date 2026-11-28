# CLA signature registry and merge check

The `CLA` GitHub Actions workflow publishes the **`cla/required`** commit status.
It checks the PR opener, commit authors, and co-authors against
[signatures.json](signatures.json) for the **exact version and SHA-256 of
[CLA.md](../../CLA.md)**. First-time contributors need a verified record; later
PRs can reuse it. Collaborators, maintainers, and bot accounts are not silently
exempted.

## Where to see who signed

- Open [signatures.json](signatures.json) for the verified signer registry.
- Open **Actions → CLA → a run → Summary** for the current-version account list
  and PR results. Display logins are provided for convenience; numeric GitHub
  account IDs determine coverage, including after a username changes.
- Follow a record's public `evidence_ref` to its signature, or ask a maintainer
  for the private record identified there. The JSON deliberately omits legal
  names and private signed documents.

Pending signatures remain in their PR comments until a maintainer verifies and
registers them; the registry is the verified list, not a list of unreviewed claims.

The registry starts empty. This does not claim that anybody has already signed,
nor that an unregistered person has never signed privately. Posting a signature
does not register it automatically: a maintainer first verifies and archives it
using the [review checklist](../CLA-MAINTAINERS.md).

## Register a verified acceptance

1. Have the contributor follow [How to sign](../../CONTRIBUTING.md#how-to-sign).
   Verify their identity, actual rights holder, employer authority, covered
   contributors, and any separate author consents. Archive the signed text and
   exact CLA as the checklist describes. The bot cannot make that legal review.
2. Obtain account IDs with `gh api users/USERNAME --jq .id`. Compute the exact
   digest of the committed CLA bytes using the command below. This avoids
   Windows checkout line-ending conversion changing the digest.
3. A maintainer adds the verified record through a reviewed PR to the default
   branch. An already verified maintainer should author that registry PR. The
   contributor's proposed registry changes in their own PR never count toward
   that PR's CLA check.
4. Once the registry PR merges, the action rechecks existing open PRs. Nobody
   needs to close and reopen a PR. `/cla recheck` as a comment also requests a
   check. The signing comment itself triggers a check, but a verified registry
   record is still required before it can pass.

```sh
python3 -c 'import hashlib, subprocess; print(hashlib.sha256(subprocess.check_output(["git", "show", "HEAD:CLA.md"])).hexdigest())'
```

Use `python` instead of `python3` if that is the Python command on Windows.

Illustrative record shape only; **do not copy this as an actual acceptance**:

```json
{
  "record_id": "cla-1.1-example",
  "cla_version": "1.1",
  "cla_sha256": "<64 lowercase hexadecimal characters from CLA.md>",
  "github_user_ids": [12345],
  "github_logins": {"12345": "example-contributor"},
  "verified_by_github_user_id": 67890,
  "verified_at": "2026-11-17T00:00:00Z",
  "evidence_ref": "private:cla-1.1-example"
}
```

Add it to the `agreements` array. A public evidence reference may instead be a
GitHub signature comment permalink. A corporate record can list several account
IDs only when the verified corporate acceptance covers their contributions.
Record only opaque private-reference IDs in public JSON; keep the actual legal
name, corporate authorization, signed text, and separate author consents in the
access-controlled archive.

For an author whose commit email is not linked to GitHub, first ask them to link
it. If that is not suitable, a maintainer may verify the identity and add
`unlinked_author_email_sha256`, mapping the SHA-256 of the stripped, lowercase
UTF-8 email to a numeric account ID already covered by the same record. Do not
guess identity from a name or use a broad email-domain exception. This map is
used only when GitHub does not identify the author; it cannot override a known
GitHub account.

If a verification record is discovered to be incorrect, remove it from the
active registry through maintainer review and preserve the audit history and
legal records. This changes what the bot trusts; it does not purport to revoke
an otherwise valid, irrevocable license grant.

## Enable actual merge enforcement (repository admin)

Adding a workflow alone does **not** prevent merges. An administrator must:

1. Merge this setup PR. Review and register the initial maintainer acceptance(s)
   before enabling the required check, so the first registry PR is not blocked
   by an empty registry. Do not fabricate signatures or auto-approve owners.
2. Open **Actions → CLA → Run workflow** on the default branch. Leave the PR
   number empty to check every existing PR. It is normal for unregistered
   accounts to receive a failing status until verified records are added.
3. In **Settings → Rules → Rulesets**, or the existing branch protection rule,
   require pull requests and the **`cla/required`** status for `main` and any
   other protected merge targets. Preserve existing required checks. Select
   **GitHub Actions** as the expected source when offered. Require branches to
   be up to date so a policy/CLA change on the base branch cannot leave an old
   green result sufficient for merging. Review bypass permissions: a bypass
   can defeat enforcement.
4. Confirm on an unsigned test PR that merging is blocked, then confirm that a
   registered account passes. The action itself never accepts an agreement for
   a contributor, changes branch protection, or merges a PR.

Until those admin settings are active, `cla/required` is advisory. The setup
operator needs repository administration permission; a Maintain role cannot
finish this settings step.

### Reviewed ruleset template

After completing the bootstrap and signature steps above, an administrator
can create the additional CLA-only ruleset using [ruleset.json](ruleset.json):

```sh
gh api --method POST repos/Yamato-Security/iwatobi/rulesets \
  --input .github/cla/ruleset.json
```

This creates an active rule for the default branch: pull requests are required,
`cla/required` must come from GitHub Actions, branches must be up to date, and
no bypass actors are added. Existing rules remain in place; their stricter
requirements still apply. Review the target branches and any existing CLA
ruleset first; do not run this again to create duplicate rules. The JSON is a
template, not an automatically applied setting. Maintain access cannot activate
it. Verify both unsigned and signed PR behavior afterward.

## Security and limitations

- Privileged PR-target and comment runs check out only the repository's default
  branch, with persisted Git credentials disabled. They never execute PR code,
  use PR artifacts, or trust a proposed signature registry in the PR head.
- The action needs only contents/PR read access plus issue-comment and commit-
  status writes. There is no external CLA service, personal access token, or
  contents-write permission. The checkout action is pinned to a full commit SHA.
- Author and commit pagination is checked. Missing/unlinked authors, incomplete
  responses, a changed CLA digest, and invalid registry data do not pass. The
  exact synthetic AI co-author email in [policy.json](policy.json) is metadata
  only; it never exempts a primary author or PR opener. GitHub links Claude's
  `noreply@anthropic.com` trailer to Anthropic's `claude` account, so that
  account's numeric ID is listed too and is skipped only for a co-author entry
  with that exact email. Do not add human authors, their accounts, or wildcards
  to either list. AI-assisted code still needs its actual rights holder's
  acceptance and provenance review.
- GitHub statuses are commit-wide. Openers of other open PRs with the same head
  also need coverage, preventing a signed duplicate PR from granting a green
  status to an unsigned opener. Closing such a PR triggers a recheck.
- The daily scan and manual dispatch cover PRs that predate installation and
  branches without the workflow. New PRs/commits trigger checks where the
  workflow is installed; keep the workflow synchronized to other base branches
  for immediate checks there. Required status settings must cover those branches.
- The check verifies recorded acceptance and listed author identities, not all
  real-world copyright ownership. Maintainers must still review employer rights,
  changed ownership, unlisted patch authors, and third-party licenses. A passed
  status is not legal clearance for every file in a proprietary release.

Run the tests with `python3 -m unittest discover -s tests/cla -v`. For a read-only
GitHub check, supply `GITHUB_TOKEN` through the environment and run
`python3 .github/scripts/cla_check.py --all-open --dry-run`.
