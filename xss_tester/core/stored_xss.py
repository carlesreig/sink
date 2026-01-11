import uuid
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from xss_tester.core.models import InjectionPoint, Finding, Payload
from xss_tester.core.injector import Injector
from xss_tester.config import REQUEST_TIMEOUT


class StoredXSSFinding(Finding):
    type: str = "stored_candidate"  # stored_candidate, stored_confirmed


class StoredXSSDetector:
    """
    Handles Stored XSS detection via passive markers and optional active confirmation.
    Acts as a fallback when Reflected/DOM checks fail.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.injector = Injector()

    def generate_marker(self) -> str:
        return f"<!--XSS_TESTER_PERSIST_{uuid.uuid4().hex[:8]}-->"

    def probe(self, point: InjectionPoint) -> StoredXSSFinding | None:
        """
        Phase 1: Passive Persistence Probe.
        Injects a non-executable marker and checks if it persists on the target page.
        """
        marker = self.generate_marker()
        payload = Payload(value=marker, category="stored_probe")

        # Use a session to maintain state (cookies) between injection and check
        with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
            self.injector.client = client
            
            # Warmup: Visit the page to get cookies/tokens if needed
            try:
                warmup_response = client.get(self.target_url, follow_redirects=True)
                self._refresh_form_tokens(warmup_response.text, point)
            except Exception:
                pass

            try:
                # 1. Inject Passive Marker
                response = self.injector.inject(point, payload)

                # 2. Check immediate response
                if marker in response.text:
                    return self._create_finding(point, payload, "Persistence marker found in immediate response")

                # 3. Check target URL (persistence check)
                check_response = client.get(self.target_url, follow_redirects=True)
                if marker in check_response.text:
                    return self._create_finding(point, payload, "Persistence marker found in target URL")
            except Exception:
                pass
            finally:
                self.injector.client = None

        return None

    def confirm(self, finding: StoredXSSFinding) -> StoredXSSFinding | None:
        """
        Phase 2: Active Confirmation.
        Injects an executable payload with a unique ID to confirm Stored XSS.
        """
        point = finding.injection_point
        uid = uuid.uuid4().hex[:8]
        payload_val = f"<img src=x onerror=alert('STORED_{uid}')>"
        payload = Payload(value=payload_val, category="stored_active")

        with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
            self.injector.client = client
            try:
                # Warmup
                warmup_response = client.get(self.target_url, follow_redirects=True)
                self._refresh_form_tokens(warmup_response.text, point)

                self.injector.inject(point, payload)

                check_response = client.get(self.target_url, follow_redirects=True)

                if payload_val in check_response.text:
                    finding.type = "stored_confirmed"
                    finding.payload = payload
                    finding.executed = True
                    finding.evidence = f"Active payload persisted: {payload_val}"
                    return finding

            except Exception:
                pass
            finally:
                self.injector.client = None

        return None

    def _refresh_form_tokens(self, html: str, point: InjectionPoint):
        """
        Updates form fields (CSRF tokens) from fresh HTML to match current session
        """
        if not point.form:
            return

        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            action_abs = urljoin(self.target_url, action)
            
            if action_abs == point.form.action and form.get("method", "get").upper() == point.form.method:
                for field in form.find_all(["input", "textarea", "select"]):
                    name = field.get("name")
                    if name and name in point.form.fields:
                        val = field.get("value")
                        if val is not None:
                            point.form.fields[name] = val
                break

    def _create_finding(self, point, payload, evidence):
        return StoredXSSFinding(
            injection_point=point,
            payload=payload,
            reflected=True,  # Technically reflected from storage
            executed=False,
            evidence=evidence
        )