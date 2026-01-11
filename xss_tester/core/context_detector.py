import re
from bs4 import BeautifulSoup, Comment

DANGEROUS_ATTRS = [
    "onerror", "onload", "onclick", "onmouseover",
    "src", "href", "style"
]

DOM_SINKS = {
    "innerHTML": r"\.innerHTML\s*=",
    "outerHTML": r"\.outerHTML\s*=",
    "document.write": r"document\.write\s*\(",
    "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
    "eval": r"\beval\s*\(",
    "setTimeout": r"\bsetTimeout\s*\(",
    "setInterval": r"\bsetInterval\s*\(",
    "location": r"(location|location\.href)\s*=",
}

ENCODINGS = {
    "&lt;": "html_entity",
    "%3C": "url_encoded",
    "\\x3c": "js_hex"
}

# --- Static Analysis Patterns ---
DOM_SOURCES = [
    r"location\.(search|hash|href)", r"document\.(URL|location|documentURI)",
    r"new\s+URLSearchParams", r"window\.location"
]

DOM_SINKS_STATIC = {
    "dom_sink.html": [
        r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
        r"\.insertAdjacentHTML\s*\("
    ],
    "dom_sink.execution": [
        r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\("
    ],
    "dom_sink.navigation": [
        r"location\.href\s*=", r"window\.location\s*=",
        r"\.attr\(\s*['\"]href['\"]\s*,", r"\.prop\(\s*['\"]href['\"]\s*,"
    ]
}


class ContextDetector:

    def detect(self, html: str, marker: str):
        soup = BeautifulSoup(html, "html.parser")

        # -------------------------------------------------
        # 1️⃣ SCRIPT (JS + DOM-XSS)
        # -------------------------------------------------
        for script in soup.find_all("script"):
            content = script.text or ""

            # DOM-XSS sink even without marker
            sink = self._detect_dom_sink(content, marker)
            if sink:
                return ("dom", sink)

            if marker in content:
                sub = self._detect_js_subcontext(content, marker)
                return ("script", sub)

        # -------------------------------------------------
        # 2️⃣ COMMENTS
        # -------------------------------------------------
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            if marker in c:
                return ("comment", None)

        # -------------------------------------------------
        # 3️⃣ ATTRIBUTES
        # -------------------------------------------------
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                val = " ".join(value) if isinstance(value, list) else str(value)

                if marker in val:
                    sub = self._detect_attr_subcontext(attr)
                    return ("html_attribute", sub)

                # DOM sink via attributes (href/src/location)
                if attr.lower() in ["src", "href"] and self._looks_like_dom_sink(val):
                    return ("dom", f"dom_sink.{attr.lower()}")

        # -------------------------------------------------
        # 4️⃣ HTML TEXT
        # -------------------------------------------------
        if marker in soup.get_text():
            return ("html_text", None)

        # -------------------------------------------------
        # 5️⃣ ENCODING
        # -------------------------------------------------
        for enc, etype in ENCODINGS.items():
            if enc in html:
                return ("encoded", etype)

        return ("unknown", None)

    # -------------------------------------------------
    # Sub-contexts
    # -------------------------------------------------

    def _detect_js_subcontext(self, script: str, marker: str):
        if re.search(rf'eval\s*\(.*{marker}', script):
            return "js_eval"
        if re.search(rf'["\'].*{marker}.*["\']', script):
            return "js_string"
        return "js_expression"

    def _detect_attr_subcontext(self, attr: str):
        attr = attr.lower()
        if attr.startswith("on"):
            return "event_handler"
        if attr in ["src", "href"]:
            return "url_attribute"
        if attr == "style":
            return "css"
        return "generic_attribute"

    # -------------------------------------------------
    # DOM-XSS detection
    # -------------------------------------------------

    def _detect_dom_sink(self, script: str, marker: str):
        for sink, pattern in DOM_SINKS.items():
            if re.search(pattern, script):
                # Marker optional → real DOM-XSS
                if marker in script or marker == "":
                    return f"dom_sink.{sink}"
        return None

    def _looks_like_dom_sink(self, value: str):
        return any(x in value.lower() for x in ["javascript:", "data:"])

    # -------------------------------------------------
    # Static JS Analysis (Hybrid Detection)
    # -------------------------------------------------
    def analyze_js_static(self, script: str) -> dict | None:
        """
        Analitza un bloc de JS per trobar fluxos Source -> Sink.
        Retorna un dict amb detalls o None.
        """
        # 1. Detect Source
        found_source = None
        for src in DOM_SOURCES:
            if re.search(src, script):
                found_source = src
                break
        
        if not found_source:
            return None

        # 2. Detect Sink
        found_sink = None
        sink_type = None
        for stype, patterns in DOM_SINKS_STATIC.items():
            for pat in patterns:
                if re.search(pat, script):
                    found_sink = pat
                    sink_type = stype
                    break
            if found_sink:
                break
        
        if not found_sink:
            return None

        # 3. Heuristic: Extract parameter name (e.g. .get('param'))
        param = None
        param_match = re.search(r"\.get\(\s*['\"]([a-zA-Z0-9_]+)['\"]\s*\)", script)
        if param_match:
            param = param_match.group(1)

        return {
            "source": found_source,
            "sink": found_sink,
            "sink_type": sink_type,
            "parameter": param
        }
