# PhishGuard URL Checker

PhishGuard is a Streamlit application that analyzes a URL for phishing-related indicators. It combines URL structure heuristics and live network checks, and can optionally ask Google Gemini for an additional assessment.

The result is a risk index and a set of findings, not a guarantee that a site is safe or malicious. A low score is not proof that a site is legitimate.

## What the app does

For each submitted URL, the app:

1. Normalizes and parses the URL. If no scheme is provided, it tries HTTPS first.
2. Runs local structural checks against the hostname and URL, including brand lookalikes, selected character substitutions, suspicious subdomains, IP-address hosts, suspicious TLDs, URL length, hyphens, sensitive keywords, and `@` user-info syntax.
3. Checks DNS resolution, TLS certificate status, and an HTTP response. The HTTP probe follows redirects, records the final URL, and checks selected response headers.
4. If the user entered an explicit HTTP URL, also probes the corresponding HTTPS URL to see if HTTPS is available. HTTPS availability is distinct from an observed HTTP-to-HTTPS redirect.
5. Produces a standalone assessment from heuristic and infrastructure findings, or uses a structured Gemini assessment if a Gemini API call succeeds.
6. Displays the verdict, threat index, infrastructure summary, findings, and recommended action. The sidebar keeps recent scan history for the current Streamlit session.

The current interface presents a single **Threat Assessment** view; it does not include separate infrastructure, structural-check, or raw JSON tabs.

## Scoring and limitations

- Risk categories are **Safe** (0–29), **Suspicious** (30–69), and **High Risk** (70–100).
- In standalone mode, the threat engine combines the heuristic score and infrastructure score using a weighted formula, with additional brand-impersonation and DNS rules.
- When Gemini returns a successful report, its assessment is generally used instead of the standalone score. The result's **Engine** indicator identifies which assessment path was used.
- For a verified HTTPS redirect or reachable HTTPS version of an HTTP URL, the app removes the HTTP-only heuristic penalty. Other independent findings are retained.
- If a scheme-less HTTPS attempt cannot be verified and an HTTP fallback responds, the app records that fallback and labels the infrastructure status as **HTTP Fallback (TLS Unverified)**.
- Brand names, official domains, suspicious TLDs, and character substitutions are maintained as hardcoded lists in `heuristics.py` and `network_intel.py`; they are not an exhaustive or automatically updated threat feed.
- Network observations can change or fail because of DNS, server rate limits, TLS configuration, network restrictions, or timeouts. A failed probe means the app could not verify that check; it does not by itself prove a site is safe or malicious.
- The score is a rule/model-based index, not a calibrated probability of phishing. Do not rely on it as the sole basis for deciding whether to visit a site or enter credentials.

## Requirements

- Python 3.9 or newer.
- Dependencies listed in `requirements.txt`.
- Optional: a Google Gemini API key for AI-assisted analysis. Without a key, the app uses the standalone heuristic and infrastructure assessment.

## Install dependencies

From the `scamcheck` project directory:

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## How to run

From the `scamcheck` project directory, activate the virtual environment if it is not already active, then start Streamlit:

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run app.py
```

### macOS or Linux

```bash
source .venv/bin/activate
python -m streamlit run app.py
```

Open the local address printed by Streamlit in your browser (normally `http://localhost:8501`). Keep the terminal running while you use the app; press `Ctrl+C` in that terminal to stop the server.

## Gemini API key

Gemini is optional. Configure a key using either:

- The **Settings** popover in the app.
- The `GEMINI_API_KEY` environment variable.
- The `GOOGLE_API_KEY` environment variable.
- A Streamlit secrets file containing `GEMINI_API_KEY`.

For local Streamlit secrets, create `.streamlit/secrets.toml`:

```toml
GEMINI_API_KEY = "your-api-key"
```

Do not commit API keys or other secrets to source control. The model selector in the app currently offers `gemini-2.5-flash` and `gemini-1.5-flash`.

## Run tests

From the project directory:

```powershell
python -m pytest test_heuristics.py -q
```

The tests cover URL heuristics, known false-positive cases, scheme-less HTTPS behavior, HTTP/HTTPS probing logic, and scoring regressions. Some separate live-verification checks in `verify_app.py` depend on network access and responses from third-party services.

## Project files

| File | Purpose |
|---|---|
| `app.py` | Streamlit interface, settings, scan history, and result presentation. |
| `heuristics.py` | URL normalization, domain parsing, rule-based indicators, and heuristic score. |
| `network_intel.py` | DNS, TLS, HTTP, redirect, and hosting-related observations. |
| `threat_engine.py` | Scan orchestration and standalone/Gemini assessment selection. |
| `gemini_analyzer.py` | Gemini client, prompt, and Pydantic report schema. |
| `test_heuristics.py` | Focused unit and regression tests. |
| `verify_app.py` | Additional verification checks, including live network and local server checks. |
| `requirements.txt` | Python package dependencies. |

## Responsible use

Only scan URLs you are authorized to assess. A scan makes network requests to the submitted host and may follow its redirects. Avoid submitting URLs that contain private tokens, passwords, or other sensitive query values. Use reputable security services and independent checks when you need a higher-confidence decision.
