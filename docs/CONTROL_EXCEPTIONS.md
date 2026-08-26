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
