import time
import yaml
from pathlib import Path
from typing import List
from tqdm import tqdm

from xss_tester.core.payload_engine import PayloadEngine
from xss_tester.core.injector import Injector
from xss_tester.core.validator import Validator
from xss_tester.core.context_detector import ContextDetector
from xss_tester.core.models import Payload, Finding, InjectionPoint
from xss_tester.config import MARKER
from xss_tester.core.colors import Colors as C


# ----------------------------------------------------------------------
# Payload loader
# ----------------------------------------------------------------------

def load_payloads(path: str | None = None) -> List[Payload]:
    """
    Carrega payloads XSS des d’un fitxer YAML
    (ruta resolta de manera absoluta, segura)
    """

    BASE_DIR = Path(__file__).resolve().parent.parent

    if path is None:
        payload_path = BASE_DIR / "payloads" / "xss.yaml"
    else:
        payload_path = Path(path).resolve()

    if not payload_path.exists():
        raise FileNotFoundError(f"Payload file not found: {payload_path}")

    payloads: List[Payload] = []

    with open(payload_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    for category, entries in raw.items():
        for entry in entries:
            val = entry["value"]
            if isinstance(val, str):
                val = val.strip()

            payloads.append(
                Payload(
                    value=val,
                    category=category,
                    expected_context=entry.get("expected_context"),
                    expected_subcontext=entry.get("expected_subcontext"),
                )
            )

    return payloads


# ----------------------------------------------------------------------
# Injection point tester
# ----------------------------------------------------------------------

def _inject_safe(injector, point, payload):
    """
    Helper per injectar i mesurar temps de forma segura.
    Retorna (response, elapsed_time) o (None, error).
    """
    try:
        start = time.time()
        response = injector.inject(point, payload)
        return response, time.time() - start
    except Exception as e:
        return None, e


def test_point(point: InjectionPoint, payloads: List[Payload]):
    """
    Funció principal per testar un punt d’injecció
    Manté:
      - marker + context detection
      - payload adaptatiu
      - validació passiva + activa
    Afegeix:
      - barra de progrés
      - temps per payload
      - early-exit intel·ligent
    Compatible amb:
      - forms complexos (POST / múltiples camps)
    """

    injector = Injector()
    validator = Validator()
    payload_engine = PayloadEngine()
    context_detector = ContextDetector()

    # ------------------------------------------------------------------
    # 1️⃣ Marker injection (reflexió + context)
    # ------------------------------------------------------------------

    marker_payload = Payload(value=MARKER, category="context")

    response, result = _inject_safe(injector, point, marker_payload)
    if response is None:
        print(f"    {C.RED}[!] Error injecting marker: {result}{C.RESET}")
        return []

    # Check reflection
    reflected = MARKER in response.text

    # Retry with slash for path parameters (common in returnPath, redirect, etc.)
    if not reflected and any(x in point.parameter.lower() for x in ["path", "url", "next", "ret", "redirect", "goto"]):
        print(f"    {C.CYAN}[*] Path parameter detected, retrying with / prefix...{C.RESET}")
        slashed_marker = Payload(value="/" + MARKER, category="context")
        response, result = _inject_safe(injector, point, slashed_marker)
        if response and MARKER in response.text:
            reflected = True
            print(f"    {C.YELLOW}[*] Marker reflected (with / prefix) ({result:.2f}s){C.RESET}")

    if not reflected:
        if point.source in ["fragment", "fragment_query", "dom_static"]:
            print(f"    {C.CYAN}[*] Fragment source: skipping reflection check{C.RESET}")
            point.context = "dom"
            if point.source != "dom_static":
                point.subcontext = "fragment"
        # Heuristic: Force check for suspicious DOM sinks even if not reflected
        elif any(x in point.parameter.lower() for x in ["return", "redirect", "next", "url", "goto"]):
            print(f"    {C.CYAN}[!] Suspicious DOM parameter (blind), forcing browser check...{C.RESET}")
            point.context = "dom"
            point.subcontext = "dom_sink.navigation"
        else:
            print(f"    {C.GREEN}[-] No reflection detected (marker) ({result:.2f}s){C.RESET}")
            return []
    else:
        print(f"    {C.YELLOW}[*] Marker reflected ({result:.2f}s){C.RESET}")
        context, subcontext = context_detector.detect(response.text, MARKER)
        point.context = context
        point.subcontext = subcontext

    # ------------------------------------------------------------------
    # 2️⃣ Payload selection segons context
    # ------------------------------------------------------------------

    selected_payloads = payload_engine.select(payloads, point)
    if not selected_payloads:
        selected_payloads = payload_engine.fallback(point)

    findings: List[Finding] = []

    # ------------------------------------------------------------------
    # 3️⃣ Payload testing amb progrés
    # ------------------------------------------------------------------

    for payload in tqdm(
        selected_payloads,
        desc=f"    Payloads [{point.parameter}]",
        leave=False
    ):
        response, elapsed = _inject_safe(injector, point, payload)
        if response is None:
            err_msg = str(elapsed)
            if "Invalid non-printable ASCII character" in err_msg:
                print(f"    {C.YELLOW}[!] Skipped payload (invalid chars for URL){C.RESET}")
            else:
                print(f"    {C.RED}[!] Error injecting payload: {err_msg}{C.RESET}")
            continue

        finding = Finding(
            injection_point=point,
            payload=payload
        )

        # Capture context before passive analysis (which might reset it if not reflected)
        pre_context = point.context
        pre_subcontext = point.subcontext

        # --- Passive analysis
        finding = validator.passive_analysis(response, finding, payload.value)

        # Restore context for blind DOM / static DOM cases if passive analysis failed to find reflection
        if not finding.reflected and (
            (pre_context == "dom" and pre_subcontext == "dom_sink.navigation") or
            point.source == "dom_static"
        ):
            finding.reflected = True
            finding.injection_point.context = pre_context
            finding.injection_point.subcontext = pre_subcontext

        if finding.reflected:
            finding = validator.active_validation(str(response.url), finding)

            if finding.executed:
                print(f"    {C.RED}{C.BOLD}[!!!] EXECUTED XSS ({elapsed:.2f}s){C.RESET}")
                findings.append(finding)
                break  # 🚀 vulnerabilitat crítica
            else:
                print(f"    {C.YELLOW}[*] Reflected (not executed) ({elapsed:.2f}s){C.RESET}")
        else:
            print(f"    {C.GREEN}[-] Not vulnerable ({elapsed:.2f}s){C.RESET}")

        findings.append(finding)

    # ------------------------------------------------------------------
    # 4️⃣ Evasion / Retry Logic (Double Encoding)
    # ------------------------------------------------------------------
    if not findings and reflected:
        print(f"    {C.CYAN}[*] No findings with standard payloads. Attempting Double Encoding...{C.RESET}")
        
        # Retry top 5 payloads
        retry_payloads = selected_payloads[:5]
        
        for payload in tqdm(retry_payloads, desc=f"    DoubleEncode [{point.parameter}]", leave=False):
            # Manual encode special chars to force double encoding by httpx
            # httpx encodes '%' as '%25', so '%27' becomes '%2527' on wire
            encoded_val = ""
            for char in payload.value:
                if not char.isalnum():
                    encoded_val += f"%{ord(char):02X}"
                else:
                    encoded_val += char
            
            de_payload = Payload(
                value=encoded_val,
                category=payload.category,
                expected_context=payload.expected_context
            )
            
            response, elapsed = _inject_safe(injector, point, de_payload)
            if response is None: continue

            finding = Finding(injection_point=point, payload=de_payload)
            
            # Check reflection (Server might return raw payload or encoded)
            if payload.value in response.text or encoded_val in response.text:
                finding.reflected = True
                finding.injection_point.context = point.context
                # Swap back to raw payload for validation matching
                finding.payload = payload
                finding.evidence = "Double URL Encoding Bypass"
                
                finding = validator.active_validation(str(response.url), finding)
                
                if finding.executed:
                    print(f"    {C.RED}{C.BOLD}[!!!] EXECUTED XSS (Double Encoded) ({elapsed:.2f}s){C.RESET}")
                    findings.append(finding)
                    break
                else:
                    print(f"    {C.YELLOW}[*] Reflected (Double Encoded) ({elapsed:.2f}s){C.RESET}")

    return findings
