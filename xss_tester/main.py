import sys
import httpx

from xss_tester.core.detector import Detector
from xss_tester.engine import load_payloads, test_point

# Definim headers HTTP per a les peticions (WAF-friendly), TODO ser configurable
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ca,en-US;q=0.7,en;q=0.3",
    "Connection": "close",
}

# definim colors per a la sortida per consola
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m xss_tester.main <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"[+] Target: {target_url}")

    # --------------------------------------------------
    # 1️⃣ Descarregar HTML (WAF-friendly)
    # --------------------------------------------------
    try:
        with httpx.Client(http2=False, headers=HEADERS, timeout=10) as client:
            response = client.get(target_url, follow_redirects=True)
    except httpx.RemoteProtocolError:
        # fallback defensiu
        with httpx.Client(http2=False, headers=HEADERS, timeout=10) as client:
            response = client.get(target_url, follow_redirects=True)

    html = response.text

    # --------------------------------------------------
    # 2️⃣ Detectar punts injectables
    # --------------------------------------------------
    detector = Detector()
    points = detector.detect(target_url, html)

    print(f"[+] Injection points found: {len(points)}")

    # --------------------------------------------------
    # 3️⃣ Carregar payloads
    # --------------------------------------------------
    payloads = load_payloads()

    # --------------------------------------------------
    # 4️⃣ Testejar cada punt
    # --------------------------------------------------
    for point in points:
        print(f"\n{C.CYAN}[>]{C.RESET} Testing {C.BOLD}{point.method}{C.RESET} {point.url} [{point.parameter}]")

        findings = test_point(point, payloads)
        if not findings:
            print(f"    {C.CYAN}[-] No reflection detected{C.RESET}")
            continue

        for f in findings:
            if f.executed:
                print(f"    {C.RED}{C.BOLD}[!!!] XSS CONFIRMED{C.RESET}")
                print(f"          {C.RED}Payload:{C.RESET} {f.payload.value}")
                print(f"          {C.YELLOW}Context:{C.RESET} {f.injection_point.context}")
                print(f"          {C.YELLOW}Risk:{C.RESET} {f.injection_point.risk_score}")
            elif f.reflected:
                print(f"    {C.YELLOW}[*] Reflected (not executed){C.RESET}")
            else:
                print(f"    {C.GREEN}[-] Not vulnerable{C.RESET}")



if __name__ == "__main__":
    main()
