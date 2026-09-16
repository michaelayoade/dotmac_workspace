# Control exceptions

A control this repository states, that some part of it currently does not obey.
Each entry names the control, what bypasses it, why the bypass was accepted, the
compensating check that keeps the bypass from drifting, an accountable **owner**,
and — the part that makes this a ledger rather than an excuse list — **the
condition under which the bypass is remediated**.

An entry with no remediation condition is not an exception. It is a rule that was
quietly rewritten. An entry with no owner is one nobody has agreed to retire.

**This ledger is append-only.** A remediated entry is marked `REMEDIATED`, dated,
and KEPT. Deleting it would erase the record that the control was ever bypassed,
which is precisely the history a reader needs when the same pressure recurs — and
would make the ledger's length a measure of present debt rather than of what this
repository has learned. Status is one of `OPEN` or `REMEDIATED`.

---

## CE-001 — the browser shell was written twice · `REMEDIATED`

**Control.** `src/dotmac_workspace/page.py`'s module docstring: the shell must
not be "two hand-written shells, because the thing they carry is not
decoration". The `<script>` tags it carries are `static/js/csrf.js`, which
copies the `csrf_token` cookie onto the `X-CSRF-Token` header that
`CSRFMiddleware` validates. A page that lost them would render mutating controls
that silently 403.

**What bypasses it.** Adopting kernel `0.1.0a97` (2026-08-26). A browser facet
must declare its shell as a real template resolved at boot, so
`templates/layouts/workspace.html` was authored. `render_page` still composes
the same document as an f-string, and every route still calls it. Two spellings
of one document now exist.

**Why it was accepted.** Rendering through `dotmac_kernel.templating.render()`
needs a `Request` that `identity.web._refusal`, `launcher.web._page` and
`operator.web._shell` do not take. Removing the duplication therefore means
rewriting three web modules and the tests that call `render_page` directly with
no app built — a surface rewrite riding along on a dependency bump, which is
precisely the coupling this adoption set out to avoid.

**Compensating check while open.** `tests/test_web_facet_shell.py` rendered both
spellings with the same inputs and required the documents to agree, plus
sensitivity proofs that the comparison bit. That controlled DRIFT. It did not
restore the control: the rule was one shell, and there were two.

**Remediation condition — met 2026-08-26.** `page.render_page` is gone. The
three `_page`/`_shell`/`_refusal` helpers take `Request` and every full page
renders `templates/layouts/workspace.html` through
`dotmac_kernel.templating.render()`. The old agreement test is deleted;
`tests/test_presentation_ownership.py` now refuses a Python document shell and
proves the declared cascade reaches the kernel's real error renderer.

**Status.** `REMEDIATED` on 2026-08-26.
**Owner.** Michael (repository owner). Reassign by editing this line; an entry
whose owner is a role nobody holds is unowned.
**Opened.** 2026-08-26, adopting kernel 0.1.0a97 (PR #13).

---

## CE-002 — one-merge CI protection recovery · `OPEN`

**Control.** `main` requires the quality, PostgreSQL, from-wheel and Governance
checks on the exact PR head, and candidate-controlled workflows receive no
Forgejo registry credential. The required-check list is strict.

**What bypasses it.** On 2026-09-16, the old CI workflow was disabled to stop
new candidate runs that would receive repository `FORGEJO_PYPI_TOKEN`. This
also stopped three required checks. Michael authorised a time-boxed exception
for **one reviewed hardening merge only**: temporarily remove those three
unavailable check contexts from branch protection while retaining Governance,
then restore the original four-context strict list immediately after that
merge. This exception never authorises re-enabling the old credentialed
workflow, a direct commit to `main`, a duplicate-name PR bootstrap check, or a
credentialed dispatch from an alternate ref.

**Why it was accepted.** The protected bundle producer and secret-free consumer
must be checked in before they can run; the disabled old workflow cannot
provide the three required contexts for the PR that installs them. Re-running
old candidate CI would reopen the credential exposure, while a PR-authored
replacement with the same check names could satisfy context-based protection
without proving the original jobs.

**Compensating check while open.** Record the exact pre-change protection
snapshot, reviewed PR head, merged SHA, actor and exception window. Keep the
old workflow disabled, require Governance green, independent security review,
and local format/lint/unit/database evidence before the single merge. Do not
change any other protection. Restore the original required contexts and
`strict=true` by API immediately after merge, then read them back before
enabling any CI workflow. The producer remains without a registry credential
until its main-only environment and source controls are verified.

**Remediation condition.** The exact four required check contexts and strict
mode are restored and read back after the one hardening merge; subsequent PRs
must produce fresh green checks from the secret-free CI before merge. Record
the exact PR, SHA and UTC window when this entry is marked `REMEDIATED`.

**Status.** `OPEN` on 2026-09-16; no branch-protection change has yet occurred.
**Owner.** Michael (repository owner).
**Opened.** 2026-09-16, explicit one-merge recovery authorisation.
