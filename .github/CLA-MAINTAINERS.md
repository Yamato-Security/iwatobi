# CLA review and recordkeeping

This checklist implements the manual acceptance process in
[CONTRIBUTING.md](../CONTRIBUTING.md). It does not establish that anyone has
already signed. The [CLA action](cla/README.md) checks records in
[signatures.json](cla/signatures.json) and publishes `cla/required`. It does not
replace your first-time signature and authority review. A repository admin must
configure that status as required before it blocks merges.

## Before adoption

- Version 1.1 keeps the commercial licensing rights and adds the community-source
  availability commitment in section 7. Review and honor both parts: accepted
  community contributions stay publicly available free of charge under RPL 1.5,
  while the same code may also be sold and used in proprietary editions. Keep a
  public release-history or source-archive copy when removing a contribution
  from the active branch, unless publication is prohibited by law or court order.
- Have counsel review [CLA.md](../CLA.md) and this signing process, including
  enforceability for the contributors and jurisdictions involved.
- Verify the recipients' legal names: Zachary Mathis and Shirofune Security
  Co., Ltd. Each receives its own license; do not substitute a GitHub organization
  name for a legal person or entity.
- Review the Japanese governing-law and exclusive first-instance Tokyo District
  Court jurisdiction clause, including its application to overseas contributors
  and any mandatory-law limits. Confirm that the signing statement includes it.
- Merge the agreed document into `main` before requesting signatures. Signers
  link an immutable `CLA.md` commit on the default branch; a proposed copy in
  a pull request is not an adopted agreement. Later legal changes require a
  new version and fresh assent; preserve earlier acceptance records.
- This is the repository's first CLA. Do not import signatures from Juntei or
  another repository: each record must cover this repository and its exact CLA.

## For each pull request

1. Identify the PR author, commit authors and co-authors, patch-providing reviewers,
   and the actual rights holders. Confirm who owns employee or contractor work
   and whether an individual retains moral rights separately from the copyright.
   A GitHub username, authorship field, bot commit, or DCO sign-off alone is not
   proof of ownership or agreement. Automated dependency updates still require
   review of the dependency's license.
2. Verify that CLA acceptances cover the licensable rights in each contribution,
   with any additional author consents required by section 5. Check that
   the authenticated signer posted their own statement, used their legal name,
   and named a full commit permalink to an adopted CLA version: `CLA.md` at a
   commit that is on `main`, not a commit that exists only in a pull
   request or another branch. If the signer represents an entity, verify their
   authority and which people and submissions the acceptance covers. If someone
   else retains moral rights, verify that person's required consent or
   non-assertion undertaking; do not treat a company's signature as an exercise
   of an individual's personal rights. A copied statement posted by somebody
   else is not a signature.
3. Archive the evidence outside contributor-editable PR content: the exact
   signed text, signer account login and numeric GitHub user ID, comment ID and
   permalink, UTC acceptance time, rights-holder and signatory names, capacity,
   contributors covered for an entity, CLA version, repository commit SHA, and a
   copy and SHA-256 digest of that version's `CLA.md`. Keep corporate authorization
   and any separate moral-rights consents privately. Never merge a contributor-provided signature ledger as
   proof that another person signed.
4. Keep a retrievable, access-controlled backup. A public comment may be edited
   or deleted; its URL alone is not an adequate archive. Retain the original
   acceptance and any later correction separately. Record which PRs/commits and
   contributors were reviewed, the reviewing maintainer, and the review date.
5. Review all third-party notices and restrictions. The CLA covers only rights
   that the signer can grant. Track imported code, fixtures, dependencies, and
   other independently licensed content separately.
6. Record on the PR that the necessary acceptances were verified, referencing
   the public signature or a private record identifier without disclosing private
   details. Add a verified entry to the default branch's
   [signature registry](cla/signatures.json) through maintainer review. The bot
   can then reuse it for later PRs; records proposed in the contributor's own PR
   do not count. Only then may the contribution be merged. If authorship or
   ownership changes before merge, repeat the affected checks.

Use records only for contribution licensing, provenance, and related legal
administration; restrict access to private identifying material.

## Earlier contributions and proprietary editions

Introducing the CLA does not relicense unsigned contributors' existing work.
Before a paid, closed-source release, inventory the relevant code, documentation,
assets, and dependencies and confirm that each is covered by an accepted CLA,
ownership, or another sufficient license. Obtain missing permissions or omit or
replace the affected material. Preserve notices and other obligations that still
apply. Keep the accepted community contributions publicly available as promised
in section 7; selling a proprietary edition does not satisfy that commitment by
itself. The commitment covers the accepted community contribution, not every
subsequent commercial modification. If transferring a Recipient's rights and
position under the agreement, require the successor or assignee to honor this
commitment. This CLA applies only to this repository. Acceptances for Juntei
or another Yamato Security repository do not automatically cover this repository.

The signed grant is irrevocable within its stated terms, but that does not cure
an invalid signature or a signer who lacked the necessary rights or authority.
