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
            payloads.append(
                Payload(
                    value=entry["value"],
                    category=category,
                    expected_context=entry.get("expected_context"),
                    expected_subcontext=entry.get("expected_subcontext"),
                )
            )

    return payloads


# ----------------------------------------------------------------------
# Injection point tester
# ----------------------------------------------------------------------

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

    try:
        start = time.time()
        response = injector.inject(point, marker_payload)
        marker_time = time.time() - start
    except Exception as e:
        print(f"    {C.RED}[!] Error injecting marker: {e}{C.RESET}")
        return []

    if MARKER not in response.text:
        if point.source in ["fragment", "fragment_query"]:
            print(f"    {C.CYAN}[*] Fragment source: skipping reflection check{C.RESET}")
            point.context = "dom"
            point.subcontext = "fragment"
        else:
            print(f"    {C.GREEN}[-] No reflection detected (marker) ({marker_time:.2f}s){C.RESET}")
            return []
    else:
        print(f"    {C.YELLOW}[*] Marker reflected ({marker_time:.2f}s){C.RESET}")
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
        try:
            start = time.time()
            response = injector.inject(point, payload)
            elapsed = time.time() - start
        except Exception as e:
            print(f"    {C.RED}[!] Error injecting payload: {e}{C.RESET}")
            continue

        finding = Finding(
            injection_point=point,
            payload=payload
        )

        # --- Passive analysis
        finding = validator.passive_analysis(response, finding, payload.value)

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

    return findings
