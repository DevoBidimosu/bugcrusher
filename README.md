# BugCrusher AI

#### Description:

> **Note:** BugCrusher AI focuses exclusively on static code and file analysis. Paste code or upload a source file, config, or Dockerfile and receive a structured security report in seconds.

BugCrusher AI is an AI-powered security analysis tool that lets anyone analyze code and configuration files for security vulnerabilities and get back a professional bug bounty report in seconds. It is built with Django on the backend and vanilla JavaScript on the frontend, and it is powered by Llama 3.3 70B running through the Groq API for free. You submit a target, the AI analyzes it, and you get severity ratings, CVSS scores, CWE identifiers, proof of concept steps, remediation guidance, and curated reference links. No security experience required to use it, and no credit card required to run it!

## Distinctiveness and Complexity

### Why This Project Is Distinct

BugCrusher AI is completely unlike any other CS50W project. It is not a social network. It is not an e-commerce site. It does not share any conceptual overlap with Mail, Commerce, Network, or Wiki. Those projects are about content, auctions, and feeds. BugCrusher AI is a security tooling application, a category that requires fundamentally different architecture, reasoning, and domain knowledge.

The application models a real professional workflow used by security researchers and bug bounty hunters every day. You submit a target, it runs through an analysis pipeline, and you receive a structured vulnerability report. This mirrors tools like Burp Suite, Snyk, and Semgrep, except it is powered by a large language model instead of static rules. No other CS50W project uses this paradigm. No other CS50W project touches the cybersecurity domain at all.

### Why This Project Is Complex

The complexity here is not just in the number of lines of code. It spans multiple systems that all have to work together at the same time.

**The AI pipeline is async and multi-step.** When you submit a scan, Django spawns a background thread that calls the Groq API with an engineered security analysis system prompt. The model returns structured JSON with an executive summary, a risk score from 0 to 100, and an array of vulnerability objects each containing severity, type, description, proof of concept, CVSS score, CWE identifier, remediation guidance, and curated reference links. That output gets parsed and written across three related database models: Scan, Vulnerability, and Report. Handling async execution, JSON parsing failures, partial responses, and accidental markdown fences from the LLM required careful defensive programming throughout ai_engine.py.

**The frontend is fully real-time without any framework.** While the scan runs in the background, JavaScript polls a Django REST endpoint every 2.5 seconds. The scan detail page shows a live terminal-style loading animation, a multi-stage progress tracker, and dynamic stage advancement all driven by poll responses. Once complete, the entire results page renders via JavaScript with no page reload at all. The Django template contains zero vulnerability data. Everything is generated from a JSON payload. The vulnerability accordion, the animated risk score bar, the severity breakdown, and all the interactive fix buttons are built in plain JS using the Fetch API, because there is a special satisfaction in doing all of that without React or jQuery!

**Code and file analysis uses language-specialized prompts.** There are 20 language-specific prompt modules in ai_engine.py, each tuned to the real CVE and CWE patterns for that language and ecosystem. Python code gets Django and Flask-specific checks. PHP gets every RCE vector including eval, preg_replace /e, and unserialize gadget chains. Terraform gets cloud misconfiguration checks for IAM wildcards and open security groups. Dockerfiles get container hardening checks. When you upload a file, the language is auto-detected from the extension — .py, .tf, .env, .yml, and 40 other extensions each route to the right module. The AI gets told exactly what to look for instead of being left to improvise from a generic checklist, which is why the results are specific rather than vague.

**The AI Fix Engine is a whole second pipeline.** After a scan completes, every vulnerability card has a button to request an AI-generated code patch. Clicking it spawns another background thread that sends the vulnerability details and the original source code back to a separate fix-focused system prompt. The model returns a JSON object with the actual fixed code, notes explaining what changed, and a verification method. Fix status is tracked per vulnerability through four states: unfixed, fixing, fixed, and wontfix. The frontend polls fix status independently and updates each card live. This was not in the original plan. I built it because after getting a list of vulnerabilities the obvious next question is "okay, how do I actually fix this?"

**The Report Import System handles four formats.** You can export any scan as JSON, HTML, Markdown, or plain text. You can also import any of those formats back and the app reconstructs a full Scan, Report, and set of Vulnerability records from the file. Each format has its own ingestion function in views.py. The JSON importer even handles a second schema called v32 external scanner format, which normalizes string references like CWE-79 into structured objects with full mitre.org URLs automatically. This feature exists because I put myself in the user's shoes and thought: what if I lose my project file? What if I want to import a scan from another tool? Real software evolves from real needs, not perfect upfront designs!

**The data model is professional grade.** The Vulnerability model stores CVSS scores, CWE identifiers, proof of concept steps, AI fix patches, fix notes, fix status, and structured reference links as a JSON field. Vulnerabilities are ordered by severity using Django's Case and When ORM expressions so critical findings always surface first. The three-model relational design reflects actual security tooling data structures, not the typical blog post models you see in course projects.

**The whole thing is mobile responsive.** The CSS includes four breakpoints: 768px for tablets, 600px for vuln card wrapping, 480px for phones, and 360px for small Android devices. The viewport meta tag is set correctly in base.html. The JS-rendered vulnerability cards handle narrow layouts correctly, with the header flex row wrapping gracefully so titles, badges, and toggles never overflow on small screens. You can test the full app on a phone and everything works.

## What Is Contained in Each File

**bugcrusher/settings.py** holds Django settings and loads the GROQ_API_KEY from the environment or a .env file via python-dotenv.

**bugcrusher/urls.py** is the root URL router that connects the scanner and users apps.

**scanner/models.py** defines the three core models. Scan tracks the target, type, status, and timestamps. Vulnerability stores every finding with its severity, CVSS, CWE, proof of concept, remediation, references as JSON, and fix fields. Report is a one-to-one with Scan holding the executive summary and risk score. Vulnerabilities are ordered by severity using Case and When.

**scanner/ai_engine.py** is the heart of the application. It contains run_scan which calls the Groq API for security analysis, and generate_fix which calls it again for code patches. Both functions run in background threads, handle JSON parsing defensively, strip accidental markdown fences, write results to the database, and handle failure states cleanly.

**scanner/views.py** contains every view in the scanner app. That includes the index page, dashboard, scan submission endpoint, scan detail page, status polling endpoint, delete endpoint, fix request endpoint, fix status polling endpoint, manual fix marking endpoint, and the import endpoint. The import endpoint dispatches to four separate ingestion functions: _ingest_json, _ingest_html, _ingest_markdown, and _ingest_txt, each of which parses a different report format and creates database records.

**scanner/admin.py** registers all three models with the Django admin and uses inlines so you can see vulnerabilities and reports directly on the scan admin page.

**scanner/migrations/** holds three migrations. The first creates all three models. The second adds the fix fields and references JSON field to Vulnerability. The third adds the input_method field to Scan for tracking whether input arrived via paste or file upload.

**users/views.py** handles login, registration, and logout using Django's built-in auth system.

**templates/base.html** is the base layout. It sets the viewport meta tag, loads fonts and the stylesheet, renders the navbar, handles Django messages, runs the matrix rain canvas animation, and includes the block hooks for page content and extra scripts.

**templates/scanner/index.html** is the landing page. For logged-in users it shows the unified code analysis form with a paste/upload toggle, a 20-language dropdown, character counter, file auto-detection, and inline error display. For visitors it shows the feature grid and call to action buttons.

**templates/scanner/dashboard.html** shows the user's scan history, a four-stat grid, a search and filter bar (by status and input method), and a scan list with status indicators, language badges, vulnerability counts, and critical badges.

**templates/scanner/scan_detail.html** shows the live progress tracker while a scan runs and an empty results container that JavaScript fills in when complete. It also handles the failed state with an error message.

**templates/scanner/import_report.html** is the import UI with a file upload input and format information.

**static/css/main.css** is the full stylesheet. It defines the terminal aesthetic using CSS custom properties for all colors, the CRT scanline overlay, the phosphor vignette, the matrix background, every component from navbars to vulnerability cards, and responsive breakpoints at 768px, 480px, and 360px.

**static/js/index.js** handles the paste/upload method toggle, the file drag-and-drop zone with language auto-detection from 40+ file extensions, the character counter for paste mode, and scan submission via Fetch. It redirects to the scan detail page on success and shows an inline error on failure.

**static/js/scan_detail.js** does the most work in the frontend. It polls the scan status endpoint, animates the terminal loading lines, advances the progress stage tracker, and when the scan completes it renders the entire results UI from the JSON payload. That includes the report header with the risk score ring, the executive summary, the severity breakdown, and every vulnerability card with its accordion, references, and fix section. It also handles export to JSON, HTML, Markdown, and plain text, and it polls fix status for any vulnerability that has a fix in progress.

**create_demo.py** seeds the database with a demo user (hunter / hunter123) and a fully completed scan with multiple vulnerabilities, a report, CVSS scores, CWE IDs, and reference links. No API key needed. This is the fastest way to see the full results UI without making a live API call.

**DEVLOG.md** is the developer journal — a narrative account of each session: decisions made, bugs discovered, architecture choices, and lessons learned. Read this to understand why the code is the way it is.

**CHANGELOG.md** is the formal changelog covering all sessions. It tracks every bug found and fixed, every feature added, and before/after metrics for each session.

**scanner/management/commands/cleanup_stale_scans.py** is a management command that marks scans stuck in the running state for over 10 minutes as failed. Run with `python manage.py cleanup_stale_scans`.

**requirements.txt** lists three packages: Django, groq, and python-dotenv.

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Get a free Groq API key

Go to [console.groq.com](https://console.groq.com), create an account, and generate a key. No credit card required. Then set it in your environment:

```bash
export GROQ_API_KEY="gsk_..."
```

Or copy .env.example to .env and fill in the key. python-dotenv loads it automatically.

### 3. Run migrations

```bash
python manage.py migrate
```

### 4. Seed demo data (recommended for graders)

```bash
python create_demo.py
```

This creates the user hunter with password hunter123 and a pre-completed demo scan. You can log in and see a full vulnerability report immediately with no API call required.

### 5. Start the server

```bash
python manage.py runserver
```

Then visit [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Additional Information

**It is completely free to run.** Groq's free tier supports thousands of requests per day. The model is llama-3.3-70b-versatile. You will not hit rate limits during normal grading use.

**The prompting strategy matters a lot.** The system prompt in ai_engine.py instructs the model to return only valid JSON with no markdown fences, and the code strips fences anyway in case it adds them. Temperature is set to 0.15 for analysis to get consistent structured output, and 0.1 for fix generation because patches need to be precise. Getting reliable structured JSON out of an LLM every single time took real iteration to get right.

**Background threads are daemon threads.** This is appropriate for a development and demo application. Scans run in the background and the frontend polls for results every 2.5 seconds until complete. The AI engine includes a 120-second hard timeout guard that automatically fails scans that hang, exponential backoff retry logic for rate limit errors (1s → 2s → 4s), and a 3-pass JSON repair system that recovers partial results when the model response is truncated mid-JSON. The test suite has 219 tests across 35 classes with 100% measured code coverage (verified by `coverage run`). The static checker in run_tests.py has 385 checks across 14 phases and enforces the coverage requirement on every run — Phase 14 invokes `coverage run` directly rather than counting test names.

**The HTML export is a complete standalone file.** When you export a scan as HTML, the result is a self-contained file with all the vulnerability data and styling embedded. You can open it in any browser with no server required. Importing it back into BugCrusher also works and reconstructs all the data.

**Ethical use.** BugCrusher AI is intended only for analyzing systems you own or have explicit written permission to test. The scan form includes a disclaimer to this effect.
