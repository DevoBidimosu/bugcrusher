# BugCrusher AI — Developer Log

A session-by-session narrative of how this project was built, hardened, overhauled, and audited. This is the story behind the code — decisions made, problems discovered, things that went wrong and how they were fixed. Not a list of changes (see CHANGELOG.md for that), but an honest account of the engineering process.

---

## Session 0 — What existed before any of this

Before the first session, BugCrusher AI was already a working application. The Django backend ran, the Groq API calls succeeded, vulnerabilities got saved to the database, the fix engine worked, the four-format import/export system was complete, and 100 tests passed. The terminal aesthetic was intact, the matrix rain animated in the background, the CVSS ring animated on scan completion.

What it was not was *polished*. The CSS had bugs that only appeared on mobile. The README was half-finished. The test coverage had a 17% hole in `users/views.py` because the auth views were never tested. The static checker had 10 phases but missed entire categories of verification. `create_demo.py` had a syntax error no one had noticed because no one had run it. And the `.env` file had a live API key in it.

The project worked as long as you used it on a desktop, never ran the demo script, and never looked at the test coverage report. Good enough for development, not good enough for submission.

---

## Session 1 — First hardening pass (March 18, 2026)

The first thing I did was read every file. Not skim — read. This decision paid off immediately and repeatedly.

**The inline style discovery.** While reading `main.css`, I wrote a new 4-breakpoint responsive system targeting the mobile layout bugs. It looked complete. The vuln header would now wrap on small screens, titles would take the full row, the toggle would stay to the right. Then I ran it and the mobile layout was still broken.

The fix was in the wrong file. The `.vuln-toggle` span was rendered by JavaScript inside `scan_detail.js`, with `style="margin-left:auto;"` hardcoded directly in the template literal string. Inline styles have higher CSS specificity than class rules. Every responsive fix I wrote was being overridden by a single attribute in a JavaScript string. Removing that one attribute unlocked the entire responsive layout.

This is the kind of bug that requires reading both files. Looking at CSS alone would never have found it. I documented it precisely because it's a good example of why "the CSS isn't working" is never a complete diagnosis.

**The SAMPLE_TXT bug.** While expanding the test suite to hit uncovered lines, I wrote a test for the TXT import parser and it failed. The parser was returning the fallback message instead of the actual executive summary. I traced it: the fixture had a `----` separator line right after `EXECUTIVE SUMMARY`. The parser's end-of-section regex `r'^[=\-]{10,}'` matched it immediately, breaking out of the loop before reading any content. The fixture was wrong, not the code. Fixed by removing the separator.

**The coverage-driven approach.** Running `coverage report -m` and targeting each uncovered line individually produced genuine new tests, not padding. 17 new test classes, each targeting a specific gap. The jump from 83% to 99% reflects real new paths being exercised.

**The API key.** The uploaded zip had a live Groq key in `.env`. Wiped it immediately. The original CHANGELOG from this session documented the full key in plaintext as an example — which I then had to redact in Session 6 because the key string itself in the documentation triggered the zip security audit.

---

## Session 2 — The V2 architecture decision (March 19, 2026)

The most significant single decision in the entire project: remove URL scanning entirely.

The VirusTotal test was the catalyst. The app returned a vulnerability report for VirusTotal.com claiming it had SQL injection and XSS vulnerabilities. Every finding was fictional. The LLM was reasoning about the URL structure — the domain name, the path segments, the query parameters — and inventing plausible-sounding vulnerabilities that had no basis in reality. For a security tool, shipping speculative fiction as security findings was worse than shipping nothing.

The alternative was a disclaimer. I considered it and rejected it. A disclaimer would say "these results may be inaccurate" while still showing the inaccurate results. That's a worse product, not an honest one.

So URL scanning went. The three-tab form (url / code / file) became a question: if code review and file upload were architecturally identical — both sent text to the same LLM — why were they two separate tabs? The only difference was input mechanism. Merging them into a single form with a paste/upload toggle was the cleaner design.

**The language specialization problem.** The original code review prompt was an 8-item generic checklist that applied to every language: "look for injection, auth flaws, crypto weaknesses..." A Python web app and a Terraform configuration have completely different threat models. Django has `@login_required`. Terraform has IAM wildcards and unencrypted EBS volumes. Sending a Dockerfile the same prompt as a Go binary wastes the model's context on irrelevant patterns and misses the relevant ones.

The LANGUAGE_FOCUS dispatch table was the solution: 20 language-specific modules, each built from real CVE and CWE patterns. Python gets Django and Flask checks. PHP gets every RCE vector including the obscure ones like preg_replace /e modifier. Terraform gets cloud misconfiguration patterns. Each module was written from actual security knowledge, not generated from a generic template.

**The reliability stack.** Three things that could fail silently before this session:
1. Groq rate limits would permanently fail a scan. Now: exponential backoff retry (1s → 2s → 4s), 3 retries before giving up.
2. Model response truncated mid-JSON. Now: 3-pass repair — close open brackets, extract partial vulns, recover what's there rather than failing.
3. Scans that hung in `running` state forever. Now: 120-second timeout guard using `threading.Timer`.

Error messages also changed. "groq.APIError: Error code: 429" became "API rate limit reached. Please wait 60 seconds." Small thing, but it's the difference between a user knowing what to do and a user thinking the app is broken.

**The file size increase.** MAX_CHARS went from 8,000 to 15,000. This was the right call but required raising max_tokens from 4,000 to 6,000. The original limit was sized for URL scan responses, which were short. A thorough code review of a 500-line file needs room to report multiple vulnerabilities with full descriptions.

---

## Session 3 — First audit pass

A shorter session, but it caught things that should have been caught earlier.

The API key had come back. Between sessions, the `.env` was restored from somewhere with the live key still in it. This is why the security audit became a permanent Phase 13 check that runs every time `run_tests.py` is executed — not just when packaging.

The `AUTH_PASSWORD_VALIDATORS = []` setting was still empty. This had been documented as something to fix but never actually fixed. A security scanning tool that accepts single-character passwords for user registration is embarrassing. `MinimumLengthValidator(min_length=8)` added.

`admin123` was still the superuser password in `create_demo.py`. Changed to `BugCrusher@2026!`.

The `vuln-toggle` inline style had reappeared. This is the same bug from Session 1 — the JavaScript template literal with `style="margin-left:auto;"`. It had been fixed, and then it came back, which means it was re-introduced during the V2 rewrite of `scan_detail.js`. Fixed again. Added it to the static checker Phase 13 so it can never silently break the mobile layout again.

---

## Session 4 — Deep audit

The theme of this session was "things that exist but are wrong."

**`strip_tags` in `_ingest_html`.** The HTML report importer used `re.sub(r'<[^>]+>', ' ', s)` to strip HTML tags. This works on well-formed HTML. It breaks on attributes containing `>` characters, which are valid in quoted attributes. Python's `html.parser` handles this correctly. The fix was straightforward: a 12-line `TagStripper` class wrapping `HTMLParser`. The regex stays as a fallback for catastrophically malformed input.

**Dashboard search and filter.** The original dashboard showed the 20 most recent scans with no way to find older ones. This became a real usability problem once test runs and demo scans accumulated. Added GET parameters: `?q=` for text search, `?status=` for status filter, `?method=` for paste/upload filter. The limit raised from 20 to 50.

**`create_demo.py` references.** The five demo vulnerabilities had CVSS scores and CWE IDs but no `references` field. The references panel in the UI would be empty for every demo vulnerability, making it look like the feature didn't work. Added structured reference objects with real CWE mitre.org and OWASP URLs to all five.

**Python syntax validation.** Action Plan item 2.1 — add `ast.parse` to `run_tests.py` Phase 1b so syntax errors are caught before packaging. This is what the `create_demo.py` SyntaxError in Session 1 should have caught automatically. Added. Now `run_tests.py` checks 14 Python files for syntax errors as its second operation.

---

## Session 5 — Deepest audit

This session introduced the line count integrity check: record exact line counts for every tracked file before touching anything, then verify after that nothing unexpectedly shrank.

The rationale: automated tests can't catch content that was present and correct becoming silently wrong. A test that checks whether `input_method` exists in the file doesn't notice if 40 lines of working functionality were accidentally deleted around it. The line count baseline does.

**`admin.py` was stale.** `list_display` still showed `target_type` and `target_type` was still in `list_filter`. After URL mode was removed, `target_type` is always "code" for every scan. These fields were useless in the admin panel. Changed to `input_method` and `language`, which are actually different across scans.

**The README had 9 stale v1 statements.** Every paragraph was written for the original 3-tab URL/code/file design:
- "scan URLs, code snippets, and files" — URL scanning was removed months ago
- "three modes" — there is one mode now
- "8,000 characters" — it's 15,000
- "two migrations" — there are three
- "three breakpoints" — there are four
- "tabbed form with URL, code, and file tabs" — it's a paste/upload toggle
- "temperature 0.2" — it's 0.15
- The `index.js` description was for the old tab-switcher
- The dashboard description didn't mention filters

All nine corrected.

**`run_tests.py` had no coverage of what it couldn't see.** Phase 8 only verified migrations 0001 and 0002. Migration 0003 — the one that adds `input_method`, the field the entire V2 architecture depends on — was never checked. Phase 2 was missing `input_method` and `INPUT_METHOD_CHOICES` field checks. Phase 7 had no template checks for the language badge, the input_method display row, or the dashboard filter bar. Added all of them.

---

## Session 6 — Documentation pass (this session)

Two things had never been done: a proper DEVLOG and a CHANGELOG that was actually inside the project.

The CHANGELOG existed as a session download artifact — a file you could find in the outputs directory but not in the project itself. If someone cloned the repository, they'd have no record of any of this work. CHANGELOG.md now lives in the project root. It covers all five sessions with metrics tables, bug tables, and complete lists of what was added, changed, and fixed.

The DEVLOG — this file — didn't exist at all. The CHANGELOG tracks *what* changed. This tracks *why*, and *what went wrong along the way*.

**The CHANGELOG key leak.** Writing the CHANGELOG required documenting the API key incident from Session 1. I wrote the original key string into the CHANGELOG as an example of what was found: `gsk_h...Vcg... (redacted)`. The zip security audit immediately flagged it. The CHANGELOG itself contained the key it was documenting. Redacted to `gsk_h...Vcg... (redacted)`.

**120 out of 122 verification checks pass automatically.** The two that don't:
1. `DEVLOG.md exists` — fixed by writing this file.
2. `README video placeholder` — still `[https://youtu.be/x]`. This one genuinely requires recording and uploading a demo, which no amount of code can do.

---

## What the static checker is

`run_tests.py` runs without Django. It reads source files directly with `open()` and checks them with `re` and string operations. 344 checks across 13+ phases. A grader with only Python installed can run it in 2 seconds and get structural verification of the entire codebase.

It started at 185 checks across 10 phases. Each session added new phases and new checks as new features were built. The checks are now broad enough that it's genuinely hard to introduce a regression without the checker catching it. Phase 1b catches syntax errors in all Python files before any other check runs. Phase 13 actively verifies that `.env` contains no real API key pattern. Phase 11 verifies the README doesn't contain stale content.

The most useful single check in the file is probably:

```python
check("scan_detail.js: no inline margin-left on vuln-toggle",
      'style=\\"margin-left:auto;\\"' not in open(...).read())
```

That one check catches the exact bug that was introduced, fixed, re-introduced, and fixed again across three separate sessions.

---

## Lessons

**Read both files.** The inline style bug required reading both `main.css` and `scan_detail.js`. Looking at only one file was why it wasn't caught sooner and why it kept coming back.

**Documentation goes stale.** The README had 9 stale statements from v1 still in it by Session 5. Every significant architectural change needs a README sweep as part of the same commit, not as a separate task.

**The zip security audit should be automated.** The API key appeared in `.env`, then in `run_tests.py` as a check string, then in `CHANGELOG.md` as documentation. Each time it appeared somewhere new it was because the previous fix didn't think about all the places the key string could propagate. The solution was to add a security audit step to the packaging process that scans every file in the zip for the key pattern.

**Changelogs should live in the project.** Having the CHANGELOG only as a session download meant it existed in Claude's outputs directory but not in the actual codebase. Documentation that isn't in the repository effectively doesn't exist.

**The DEVLOG and CHANGELOG serve different readers.** The CHANGELOG is for someone who wants to know exactly what changed in which file. The DEVLOG is for someone who wants to understand why, what went wrong, and what to avoid next time.

---

*Written March 19, 2026 — Session 6*
*BugCrusher AI — CS50W Capstone, Django + Vanilla JS + Llama 3.3 70B via Groq*


---

## Session 8 — The coverage number was a lie

There's a particular discomfort that comes from discovering that a metric you've been reporting confidently is wrong. The "99% coverage" claim survived every previous audit pass because no audit checked it the right way. The static checker counted the number of `def test_` functions in tests.py and verified that number was `≥ 164`. That is not coverage measurement. That is test counting. They are completely different things.

Running `python -m coverage run` for the first time in this session showed the real number: 97% overall, with `scanner/ai_engine.py` at 84% and the management command at 0%. The management command had never been exercised by a single test. It had existed in the project for multiple sessions, been checked for existence and content by the static checker, and been reported as "complete" — but nothing had ever run it.

The 84% on `ai_engine.py` was the more interesting finding. It revealed which paths the existing tests couldn't reach:

The retry backoff body (`time.sleep(2 ** attempt)`) required a mock that raised a transient error on the first call and succeeded on the second. None of the existing retry tests did this — they either always failed or always succeeded. The sleep line was visible in the source but invisible to coverage because the test setup never actually triggered the conditional.

The `_on_timeout` callback body is a nested function defined inside `run_scan`. Coverage tools track line execution, not definition. Defining the function doesn't execute its body. To execute the body, the `threading.Timer` has to fire the callback. In production this happens after 120 seconds. In tests, you need to patch `Timer` to call the callback immediately. This required a small refactor to make the timeout duration configurable via a Django setting, which made the test setup clean.

Pass 2 of `_parse_or_repair_json` contained a real bug discovered during this session. The code appended `}` characters before `]` characters when trying to close an uncovered object. For JSON that ends inside a nested array like `{"vulnerabilities": [`, the correct closing is `]}` (close the array first, then the object). The code was generating `}]` (close the object first), producing `{"vulnerabilities": [}]` which is invalid JSON. The fix tries both orderings. The bug had been present since the Pass 2 feature was written and had never been caught because no test used an input that required closing both a bracket and a brace.

Two lines were truly unreachable:

`raise last_error` after a for-loop where every iteration either returns or raises. The loop can only exit by exhausting its range, but in that case the last iteration's `raise` inside the loop already propagated. The `raise last_error` after the loop was dead code. Removed.

The inner `except Exception` on `latin-1` decoding. Latin-1 is a fixed 256-codepoint encoding that maps every possible byte value. It literally cannot raise a decode error. The except was written defensively but was permanently unreachable. Replaced with `decode('latin-1', errors='replace')` which makes the intent clearer and removes the dead branch.

The lesson here is that the static checker was enforcing the wrong thing. Counting tests is not the same as measuring coverage. Phase 14 now runs `coverage run` via subprocess and calls `coverage report --fail-under=100`. The number is measured, not claimed. If someone writes a test that doesn't execute any new lines, the count goes up but the coverage stays the same. Phase 14 catches this. Phase 10's count threshold is a lower bound on effort; Phase 14 is the actual correctness gate.

Final numbers: 219 tests, 385 static checks, 100% measured coverage. Every production line executes under test.
