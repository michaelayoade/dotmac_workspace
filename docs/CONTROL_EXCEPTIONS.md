# Control exceptions

A control this repository states, that some part of it currently does not obey.
Each entry names the control, what bypasses it, why the bypass was accepted, the
compensating check that keeps the bypass from drifting, and — the part that
makes this a ledger rather than an excuse list — **the condition under which the
entry is deleted**.

An entry with no retirement condition is not an exception. It is a rule that was
quietly rewritten.

---

## CE-001 — the browser shell is written twice

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

**Compensating check.** `tests/test_web_facet_shell.py` renders both spellings
with the same inputs and requires the documents to agree, plus sensitivity
proofs that the comparison bites. This controls DRIFT. It does not restore the
control: the rule is one shell, and there are two.

**Retirement condition.** Delete this entry when `page.render_page` is gone and
every browser route renders the facet shell through
`dotmac_kernel.templating.render()`. That change is a `Request` threaded through
the three `_page`/`_shell`/`_refusal` helpers and their tests, and it is worth
doing on its own footing rather than here. `tests/test_web_facet_shell.py` goes
with it — an agreement test between one thing and itself is noise.

**Owner.** Unassigned. **Opened.** 2026-08-26, adopting kernel 0.1.0a97.
