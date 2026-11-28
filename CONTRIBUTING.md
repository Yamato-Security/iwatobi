# Contributing to Iwatobi

Bug reports, fixes, documentation, tests, new log formats and new rules are
welcome. Keep pull requests focused, describe the detection or parsing behavior
being changed, and include test logs with the expected detections for parser and
rule changes. Do not upload private logs, credentials, or data You do not have
permission to share.

## Contributor License Agreement

Before we merge contributed material, we require acceptance of the
[Iwatobi Contributor License Agreement](CLA.md) (CLA) covering the rights being
licensed, along with any additional authorizations or author consents required
by section 5. This includes code, documentation, tests, and artwork. A bug report
that only describes a problem and does not supply material for incorporation
does not require a signature.

The CLA gives **Zachary Mathis** and **Shirofune Security Co., Ltd.** independent
permission to use and relicense Your Contributions, including in **paid,
proprietary, closed-source products and services**. You keep ownership of Your
work. **Your accepted contributions will also remain available in the free,
open-source Iwatobi community edition.** The commercial copy may be sold or
distributed under a closed-source license without withdrawing the community
copy. Proprietary additions and later modifications to commercial editions need
not be published under the CLA. Read the full agreement before signing.

The CLA selects Japanese law and the Tokyo District Court as the exclusive court
of first instance for disputes under the agreement, subject to mandatory
applicable law.

The CLA is separate from Iwatobi's public [RPL 1.5 license](LICENSE). It grants
additional rights to the named recipients; it does not change existing public
releases or remove third-party license obligations.

## How to sign

Sign once for version 1.1; it covers Your own past and future contributions to
this repository. Each contributor signs for their own rights. If You do not own
the relevant rights, an authorized representative of the rights holder must
sign, or provide written authorization that covers this agreement.

1. Open a pull request and read [CLA.md](CLA.md).
2. Open [`CLA.md` on `main`](https://github.com/Yamato-Security/iwatobi/blob/main/CLA.md),
   whichever branch Your pull request targets. Sign only an agreement already
   adopted on the default branch, not a proposed copy in a pull request. Press
   **Y** in GitHub to obtain its permalink and copy that URL. It must identify
   a full commit SHA, not a moving branch name.
3. Post the following statement as a new comment **from Your own GitHub account**.
   Replace the bracketed fields. Use the private process below if the identifying
   information should not be public.

```text
I have read the Iwatobi Contributor License Agreement, version 1.1,
at [full commit permalink to CLA.md]. I accept that agreement on behalf of the
rights holder identified below, either for myself or as its authorized
representative. I have authority to make this acceptance and intend this
comment as my electronic signature of it.

The rights holder grants the rights in that agreement, including permission
for Zachary Mathis and Shirofune Security Co., Ltd. to use and relicense its
covered contributions in paid, proprietary, closed-source products and services.
I understand that the accepted contributions will also remain available in the
free, open-source community edition under section 7; commercial editions and
their proprietary additions or later modifications need not be published.
This acceptance covers the rights holder's past and future contributions to
Yamato-Security/iwatobi to the extent it owns or is authorized to license them.
The rights holder also agrees to the Japanese governing law and exclusive
first-instance jurisdiction of the Tokyo District Court specified in the
agreement, subject to its mandatory-law qualification.

Legal name of the rights holder: [individual's full name or legal entity name]
Signer's full name: [full name]
GitHub account: @[username]
Capacity: [signing for myself, or role and authority to sign for the entity]
Contributors covered: [entity only: GitHub accounts of covered contributors]
```

4. A maintainer verifies and archives the acceptance. On later pull requests,
   the **`cla/required` GitHub Actions check** reuses the verified record in
   [.github/cla/signatures.json](.github/cla/signatures.json). A missing record
   fails the check; signing alone does not pass it before maintainer verification
   and registration. Re-sign if the rights holder changes or if You agree to a
   different version. Existing PRs do not need reopening; comment `/cla recheck`
   after registration if needed.

This is the first CLA adopted by this repository. Its version 1.1 follows
Juntei's commercial-licensing and community-availability approach, but it
covers only **Yamato-Security/iwatobi**. An acceptance for Juntei or another
Yamato Security repository is not a signature to this agreement.

**A PR-template checkbox, a `Signed-off-by` line, a maintainer's comment on Your
behalf, or opening a pull request alone is not the required acceptance.** For a
multi-author pull request, identify all contributors and their rights holders;
one person's signature cannot cover others' independently owned contributions.
Reviewers who submit patches must also be covered before those patches are used.

### Employer or corporate ownership

Obtain permission before signing when an employer or client owns Your work.
An authorized representative may use the same statement on behalf of the legal
entity and identify the contributors and contributions covered. Merely listing
a company name or having a company email address does not establish authority.

If an individual author retains moral rights while a company owns the
copyright, the company's acceptance alone cannot waive or restrict that
individual's rights. Identify that situation and arrange the necessary consent
or non-assertion undertaking from the actual author. An existing authorization
may suffice if it covers the uses under this CLA; a maintainer must verify it.

### Private acceptance

If Your legal name, corporate authorization, or signature must be private, ask a
maintainer to arrange a private signing channel. Do not post addresses, identity
documents, or confidential employment paperwork in a public issue or PR. The
maintainer must retain the signed agreement and confirm coverage on the PR
before merging and register an opaque private reference for the automated
check. No private signed documents or legal names belong in the public registry.

## Third-party and earlier material

Disclose the source and license of copied or adapted material, libraries,
fixtures, datasets, and generated material that carries third-party terms.
Keep their copyright and license notices. The CLA does not give You authority
to relicense someone else's material. Rules copied from SigmaHQ keep their
authors and the Detection Rule License.

Existing contributors are asked to sign for their own earlier submissions.
Until the relevant rights holders have agreed or another sufficient license is
established, their contributions remain governed by their existing licenses.
Do not assume that introducing a CLA clears the repository's entire history for
a proprietary edition.

## Before merging

Maintainers must follow the [CLA review and recordkeeping checklist](.github/CLA-MAINTAINERS.md).
The **`cla/required` check** verifies recorded acceptance for the current CLA and
listed PR authors. A repository administrator must make it a required status
check for it to block merging. Maintainers still manually verify first-time
acceptances, rights-holder authority, author consents, and third-party
restrictions. See [bot setup and the verified signer list](.github/cla/README.md).
Do not merge contributed material until those reviews are complete.
