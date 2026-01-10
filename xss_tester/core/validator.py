from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from xss_tester.core.models import Finding
from xss_tester.core.context_detector import ContextDetector
from xss_tester.core.execution_triggers import ExecutionTriggerEngine
from xss_tester.core.dom_discovery import DOMDiscovery
from xss_tester.config import PLAYWRIGHT, RISK_SCORE
import time


class Validator:
    """
    XSS Validator (Clean Auditor version)

    Detecta execució JS real mitjançant:
      - dialogs (alert / confirm / prompt)
      - console side-effects
      - globals JS
      - DOM mutations
      - DOM-XSS sinks
      - delayed / client-side execution
    """

    # ------------------------------------------------------------------
    # Passive analysis
    # ------------------------------------------------------------------
    def passive_analysis(self, response, finding: Finding, marker: str):
        detector = ContextDetector()
        context, subcontext = detector.detect(response.text, marker)

        finding.reflected = marker in response.text
        finding.injection_point.context = context
        finding.injection_point.subcontext = subcontext
        finding.injection_point.risk_score = self._calculate_risk(context, subcontext)

        if finding.reflected:
            finding.evidence = f"Payload reflected in {context} ({subcontext})"

        return finding

    # ------------------------------------------------------------------
    # Active validation (Playwright – deep JS)
    # ------------------------------------------------------------------
    def active_validation(self, url: str, finding: Finding):
        executed = False
        evidence = []

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=PLAYWRIGHT["headless"]
            )
            context = browser.new_context()
            page = context.new_page()

            try:
                # ------------------------------------------------------
                # 1️⃣ Inject Hooks BEFORE Navigation (CRITICAL FIX)
                # ------------------------------------------------------
                page.add_init_script("""
                    (() => {
                        window.__xss = { triggered: false, reasons: [] };

                        const flag = (reason) => {
                            window.__xss.triggered = true;
                            window.__xss.reasons.push(reason);
                        };

                        // Dialogs
                        window.alert = () => flag("alert()");
                        window.confirm = () => flag("confirm()");
                        window.prompt = () => flag("prompt()");

                        // Console
                        const origLog = console.log;
                        console.log = function(msg) {
                            if (String(msg).includes("XSS")) flag("console.log");
                            origLog.apply(console, arguments);
                        };

                        // DOM-XSS sinks (SAFE)
                        const hook = (obj, prop) => {
                            const original = obj[prop];
                            obj[prop] = function() {
                                flag(prop);
                                return original.apply(this, arguments);
                            };
                        };

                        hook(window, "eval");
                        hook(window, "setTimeout");
                        hook(window, "setInterval");
                        hook(document, "write");

                        ["innerHTML", "outerHTML"].forEach(prop => {
                            const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
                            Object.defineProperty(Element.prototype, prop, {
                                set(value) { flag(prop); return desc.set.call(this, value); },
                                get() { return desc.get.call(this); }
                            });
                        });

                        const origInsert = Element.prototype.insertAdjacentHTML;
                        Element.prototype.insertAdjacentHTML = function() {
                            flag("insertAdjacentHTML");
                            return origInsert.apply(this, arguments);
                        };

                        const observer = new MutationObserver(() => { flag("DOM mutation"); });
                        observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
                    })();
                """)

                # ------------------------------------------------------
                # 2️⃣ Load page
                # ------------------------------------------------------
                page.goto(
                    url,
                    timeout=PLAYWRIGHT["page_timeout"],
                    wait_until="domcontentloaded"
                )

                # Check execution immediately (onload events)
                executed, evidence = self._observe_execution(page, extra_time=0.5)

                if not executed:
                    # ------------------------------------------------------
                    # 3️⃣ Passive DOM discovery
                    # ------------------------------------------------------
                    try:
                        page.evaluate("() => { window.__xss_discovery = true; }")
                        discovery = DOMDiscovery()
                        finding.injection_point.dom_features = discovery.run(page)
                    except Exception:
                        finding.injection_point.dom_features = []
                    finally:
                        page.evaluate("() => { window.__xss_discovery = false; }")

                    # ------------------------------------------------------
                    # 4️⃣ Autopopulate payload.requires
                    # ------------------------------------------------------
                    self._autopopulate_requires(finding)

                    # ------------------------------------------------------
                    # 5️⃣ Trigger phase (REAL execution)
                    # ------------------------------------------------------
                    trigger_engine = ExecutionTriggerEngine()
                    try:
                        trigger_engine.try_triggers(page, finding.injection_point)
                    except Exception:
                        pass

                    executed, evidence = self._observe_execution(page)

                # ------------------------------------------------------
                # 6️⃣ Aggressive DOM-XSS (fallback)
                # ------------------------------------------------------
                if finding.reflected and not executed:
                    try:
                        self._aggressive_dom_xss(page)
                    except Exception:
                        pass

                    executed, evidence = self._observe_execution(
                        page,
                        extra_time=PLAYWRIGHT.get("js_observe_time_aggressive", 3)
                    )

            except PlaywrightTimeout:
                finding.evidence = "Playwright timeout during navigation"

            except Exception as e:
                finding.evidence = f"Playwright error: {e}"

            finally:
                browser.close()

        # ----------------------------------------------------------
        # 7️⃣ Final verdict
        # ----------------------------------------------------------
        if executed:
            finding.executed = True
            finding.evidence = " | ".join(set(evidence))
            finding.injection_point.risk_score = min(
                finding.injection_point.risk_score + 3,
                10
            )

        return finding

    # ------------------------------------------------------------------
    # Autopopulate payload.requires from DOM discovery
    # ------------------------------------------------------------------
    def _autopopulate_requires(self, finding: Finding):
        if finding.payload.requires:
            return

        requires = []
        for feature in getattr(finding.injection_point, "dom_features", []):
            if feature.startswith(("event:", "interaction:", "element:")):
                requires.append(feature)
        finding.payload.requires = list(set(requires))

    # ------------------------------------------------------------------
    # Aggressive DOM-XSS triggers (SAFE)
    # ------------------------------------------------------------------
    def _aggressive_dom_xss(self, page):
        page.evaluate("""
            () => {
                const events = ["mouseover","mouseenter","focus","blur","scroll","animationstart"];
                document.querySelectorAll("*").forEach(el => {
                    events.forEach(evt => {
                        try { el.dispatchEvent(new Event(evt, { bubbles: true })); } catch(e) {}
                    });
                });
                document.body.offsetHeight;
                setTimeout(() => {}, 10);
                setInterval(() => {}, 10);
                document.querySelectorAll("[onload],[onerror]").forEach(el => {
                    try { el.dispatchEvent(new Event("load")); el.dispatchEvent(new Event("error")); } catch(e) {}
                });
            }
        """)

    # ------------------------------------------------------------------
    # Observe execution
    # ------------------------------------------------------------------
    def _observe_execution(self, page, extra_time=None):
        evidence = []
        executed = False
        end_time = time.time() + (extra_time or PLAYWRIGHT.get("js_observe_time", 4))
        while time.time() < end_time:
            state = page.evaluate("window.__xss")
            if state["triggered"]:
                executed = True
                evidence.extend(state["reasons"])
                break
            time.sleep(0.2)
        return executed, evidence

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    def _calculate_risk(self, context: str, subcontext: str | None):
        score = RISK_SCORE.get(context, 1)
        if subcontext:
            if subcontext.startswith("dom"):
                score = max(score, RISK_SCORE.get("dom_sink", 9))
            else:
                score = max(score, RISK_SCORE.get(subcontext, score))
        return min(score, 10)
