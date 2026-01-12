**XSS Tester – Smart XSS Detection Framework**

XSS Tester is a modular and extensible security testing tool designed to detect, validate, and classify Cross-Site Scripting (XSS) vulnerabilities in modern web applications.
Unlike simple scanners, it combines context-aware payload injection, adaptive testing, and real JavaScript execution validation.

**🔍 Key Features**

**Automatic Injection Point Discovery**

Detects GET and POST parameters, including complex HTML forms.
Handles multiple injection points per endpoint.

**Context-Aware XSS Detection**

Injects a unique marker to identify reflection points.
Automatically detects HTML, attribute, JavaScript, and DOM contexts.
Adapts payloads based on the detected context and subcontext.

**Adaptive Payload Engine**

Selects the most effective payloads depending on where and how user input is reflected.
Fallback mechanisms ensure coverage even in ambiguous contexts.
Payloads are fully configurable via YAML.

**Passive + Active Validation**

Passive analysis detects reflection, encoding, and sanitization behavior.
Active validation uses Playwright to confirm real JavaScript execution, not just reflection.
Detects alert, confirm, prompt, and execution side effects safely.

**DOM-XSS Ready Architecture**

Designed to support DOM sinks such as: innerHTML, document.write, location, eval / setTimeout
Clean separation between detection, injection, and validation logic.

**Risk Scoring**

Automatically assigns a risk score based on context and sink severity.
Helps prioritize findings in real-world assessments.

**Performance-Aware Testing**

Early-exit logic when critical XSS is confirmed.
Progress bars and per-payload timing for long scans.
Optimized to reduce unnecessary requests.

**Why It’s Different**

Goes beyond “reflected = vulnerable” logic.
Confirms actual exploitability in a real browser environment.
Built with clean architecture, making it easy to extend with new payloads, contexts, or vulnerability classes (DOM-XSS, CSP bypasses, etc.).

**Ideal For**

- Security researchers and pentesters
- Students learning web security internals
- Custom audits where accuracy matters more than noisy scans

**INSTALL**
```bash
git clone https://github.com/carlesreig/xss-tester --depth=1
python3 -m venv ENTORN
source ENTORN/bin/activate
# inside (venv) user@localhost
pip3 install -r requirements.txt
playwright install
# your target inside "target.com"
python3 -m xss_tester.main "https://DOMAIN.TLD"
```
