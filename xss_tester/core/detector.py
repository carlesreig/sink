import httpx
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from .models import InjectionPoint, Form
from .context_detector import ContextDetector


class Detector:

    def __init__(self):
        # Client intern per fer crawling lleuger d'iframes
        self.client = httpx.Client(timeout=5.0, verify=False)

    def detect(self, url: str, html: str) -> list[InjectionPoint]:
        soup = BeautifulSoup(html, "html.parser")
        points: list[InjectionPoint] = []
        seen: set[tuple[str, str, str]] = set()

        def add_point(point: InjectionPoint):
            key = (point.method, point.url, point.parameter)
            if key not in seen:
                seen.add(key)
                points.append(point)

        # --------------------------------------------------
        # FASE 1: URL & Fragment (DOM-based)
        # --------------------------------------------------
        self._scan_url_and_fragments(url, soup, add_point)

        # --------------------------------------------------
        # FASE 2: Formularis (Main DOM)
        # --------------------------------------------------
        self._scan_forms(url, soup, add_point, surface="main")

        # --------------------------------------------------
        # FASE 3: Iframes (Crawling & Recursion)
        # --------------------------------------------------
        self._scan_iframes(url, soup, add_point)

        # --------------------------------------------------
        # FASE 4: Static JS Analysis (DOM-XSS)
        # --------------------------------------------------
        self._scan_static_js(url, soup, add_point)

        return points

    # ----------------------------------------------------------------------
    # FASE 1: URL & Fragment Analysis
    # ----------------------------------------------------------------------
    def _scan_url_and_fragments(self, url, soup, add_point):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 1.1 URL Parameters (Server-side Reflected)
        params = parse_qs(parsed.query)
        for param in params:
            add_point(InjectionPoint(
                url=base_url,
                method="GET",
                parameter=param,
                source="url_param",
                attack_surface="main",
                confidence="certain"
            ))

        # 1.2 Fragment Analysis (DOM-based XSS)
        fragment = parsed.fragment
        has_fragment = bool(fragment)

        # Millora: Detectar fonts DOM (Sources) en JS i Events
        dom_patterns = [
            "location.hash", "location.href", "location.search",
            "document.URL", "document.documentURI", "baseURI",
            "onhashchange", "URLSearchParams"
        ]
        uses_dom_source = False

        # 1. Buscar en scripts
        for script in soup.find_all("script"):
            if script.text and any(p in script.text for p in dom_patterns):
                uses_dom_source = True
                break

        # 2. Buscar en events HTML (onclick, onload, etc.)
        if not uses_dom_source:
            for tag in soup.find_all():
                for attr, val in tag.attrs.items():
                    if attr.startswith("on") and any(p in str(val) for p in dom_patterns):
                        uses_dom_source = True
                        break

        # Punt d'injecció genèric al fragment
        if has_fragment or uses_dom_source:
            query = f"?{parsed.query}" if parsed.query else ""
            target_url = f"{base_url}{query}"
            
            # Si hem detectat ús de DOM, pugem la confiança
            confidence = "certain" if uses_dom_source else "potential"

            add_point(InjectionPoint(
                url=target_url,
                method="GET",
                parameter="#fragment",
                source="fragment",
                attack_surface="main",
                confidence=confidence
            ))

        # 1.3 Parse parameters INSIDE fragment (SPA / Hash params)
        # Cas A: #/search?q=test
        # Cas B: #access_token=123
        if has_fragment:
            frag_query = ""
            path_part = fragment

            if "?" in fragment:
                path_part, frag_query = fragment.split("?", 1)
            elif "=" in fragment:
                # Assumim format key=value directament al hash
                frag_query = fragment

            if frag_query:
                frag_params = parse_qs(frag_query)
                fragment_base = f"{base_url}#{path_part}"

                for param in frag_params:
                    add_point(InjectionPoint(
                        url=fragment_base,
                        method="GET",
                        parameter=param,
                        source="fragment_query",
                        attack_surface="main",
                        confidence="certain"
                    ))

    # ----------------------------------------------------------------------
    # FASE 2: Form Analysis
    # ----------------------------------------------------------------------
    def _scan_forms(self, base_url, soup, add_point, surface="main"):
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            action = urljoin(base_url, action)
            method = form.get("method", "get").upper()

            fields = {}
            injectable = []

            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                
                value = field.get("value")
                # Handle textarea content if value attr is missing
                if field.name == "textarea" and not value:
                    value = field.text

                if not value:
                    # Heuristics for default values to pass validation
                    field_type = field.get("type", "").lower()
                    name_lower = name.lower()
                    
                    if field_type == "email" or "email" in name_lower:
                        value = "test@example.com"
                    elif "url" in name_lower or "website" in name_lower:
                        value = "http://example.com"
                    elif "date" in name_lower:
                        value = "2024-01-01"
                    elif "number" in field_type or "id" in name_lower:
                        value = "1"
                    else:
                        value = "test"

                if field.get("type", "").lower() not in ("submit", "button", "hidden"):
                    injectable.append(name)
                fields[name] = value

            if injectable:
                form_obj = Form(action=action, method=method, fields=fields, injectable_fields=injectable)
                for name in injectable:
                    add_point(InjectionPoint(
                        form=form_obj, url=action, method=method, parameter=name,
                        source="form", attack_surface=surface, confidence="certain"
                    ))

    # ----------------------------------------------------------------------
    # FASE 3: Iframe Discovery
    # ----------------------------------------------------------------------
    def _scan_iframes(self, base_url, soup, add_point):
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src")
            if not src or src.startswith(("javascript:", "data:")):
                continue

            iframe_url = urljoin(base_url, src)
            
            # Només analitzem iframes del mateix domini (seguretat/scope)
            if urlparse(iframe_url).netloc == urlparse(base_url).netloc:
                try:
                    resp = self.client.get(iframe_url)
                    if resp.status_code == 200:
                        iframe_soup = BeautifulSoup(resp.text, "html.parser")
                        # Recursivitat limitada: analitzem forms dins l'iframe
                        self._scan_forms(iframe_url, iframe_soup, add_point, surface="iframe")
                        # També podríem analitzar params de la URL de l'iframe
                        self._scan_url_and_fragments(iframe_url, iframe_soup, add_point)
                except Exception:
                    pass

    # ----------------------------------------------------------------------
    # FASE 4: Static JS Analysis
    # ----------------------------------------------------------------------
    def _scan_static_js(self, base_url, soup, add_point):
        detector = ContextDetector()
        
        # Collect all JS content (inline scripts + event handlers)
        scripts = [s.text for s in soup.find_all("script") if s.text]
        for tag in soup.find_all():
            for attr, val in tag.attrs.items():
                if attr.startswith("on"):
                    scripts.append(str(val))

        for script in scripts:
            result = detector.analyze_js_static(script)
            if result:
                # Determine confidence based on sanitization checks
                is_sanitized = any(re.search(p, script) for p in [
                    r"startsWith\(", r"escape\(", r"encodeURIComponent\(", 
                    r"whitelist", r"^[a-zA-Z0-9_-]+$"
                ])
                
                confidence = "low" if is_sanitized else "high"
                
                # If we identified a specific parameter being passed to a sink
                if result["parameter"]:
                    add_point(InjectionPoint(
                        url=base_url,
                        method="GET",
                        parameter=result["parameter"],
                        source="dom_static",
                        context="dom",
                        subcontext=result["sink_type"],
                        attack_surface="main",
                        confidence=confidence
                    ))
                
                # Note: If no parameter is found, we could flag the URL itself, 
                # but we prioritize actionable parameter-based findings.
