import sys
import httpx
import argparse
import concurrent.futures

from xss_tester.core.detector import Detector
from xss_tester.engine import load_payloads, test_point
from xss_tester.core.colors import Colors as C
from xss_tester.config import VERSION, STOP_ON_FIRST_CONFIRMED
from xss_tester.core.stored_xss import StoredXSSDetector

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


def main():
    print(f"{C.BLUE}{C.BOLD}XSS Tester v{VERSION}{C.RESET}")

    parser = argparse.ArgumentParser(description="Advanced XSS Detection Tool")
    parser.add_argument("target_url", help="The target URL to scan")
    parser.add_argument("--confirm-stored", action="store_true", help="Enable active confirmation for Stored XSS")
    
    args = parser.parse_args()

    target_url = args.target_url
    confirm_stored = args.confirm_stored

def scan_target(target_url, confirm_stored, payloads):
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        print(f"{C.YELLOW}[*] No scheme detected, defaulting to: {target_url}{C.RESET}")

    print(f"[+] Scanning Target: {target_url}")

    target_findings = []
    # --------------------------------------------------
    # 1️⃣ Descarregar HTML (WAF-friendly)
    # --------------------------------------------------
    client_opts = {"http2": False, "headers": HEADERS, "timeout": 10}
    try:
        try:
            with httpx.Client(**client_opts) as client:
                response = client.get(target_url, follow_redirects=True)
        except httpx.RemoteProtocolError:
            # fallback defensiu
            with httpx.Client(**client_opts) as client:
                response = client.get(target_url, follow_redirects=True)
    except httpx.ConnectError:
        print(f"{C.RED}[!] Connection refused for {target_url}.{C.RESET}")
        return []
    except httpx.RequestError as e:
        print(f"{C.RED}[!] Error connecting to {target_url}: {e}{C.RESET}")
        return []

    html = response.text

    # --------------------------------------------------
    # 2️⃣ Detectar punts injectables
    # --------------------------------------------------
    detector = Detector()
    points = detector.detect(target_url, html)

    print(f"[+] Injection points found for {target_url}: {len(points)}")

    # --------------------------------------------------
    # 3️⃣ Carregar payloads
    # --------------------------------------------------
    payloads = load_payloads()

    # --------------------------------------------------
    # 5️⃣ Initialize Stored XSS Detector
    # --------------------------------------------------
    stored_detector = StoredXSSDetector(target_url)

    # --------------------------------------------------
    # 4️⃣ Testejar cada punt
    # --------------------------------------------------
    for point in points:
        print(f"\n{C.CYAN}[>]{C.RESET} [{target_url}] Testing {C.BOLD}{point.method}{C.RESET} {point.url} [{point.parameter}]")

        findings = test_point(point, payloads)
        target_findings.extend(findings)

        vulnerability_found = False
        for f in findings:
            if f.executed:
                vulnerability_found = True
                print(f"          {C.RED}[{target_url}] Payload:{C.RESET} {f.payload.value}")
                print(f"          {C.YELLOW}[{target_url}] Context:{C.RESET} {f.injection_point.context}")
                print(f"          {C.YELLOW}[{target_url}] Risk:{C.RESET} {f.injection_point.risk_score}")

        if vulnerability_found and STOP_ON_FIRST_CONFIRMED:
            print(f"\n{C.GREEN}[*] Vulnerability confirmed. Stopping scan for this target.{C.RESET}")
            break

        # --------------------------------------------------
        # Stored XSS Fallback (Intelligent Probe)
        # --------------------------------------------------
        if not findings and (point.method == "POST" or point.form):
            probe_finding = stored_detector.probe(point)
            if probe_finding:
                print(f"    {C.RED}[!] [{target_url}] STORED XSS CANDIDATE DETECTED (Passive){C.RESET}")
                print(f"          Marker: {probe_finding.payload.value}")

                if confirm_stored:
                    print(f"    {C.BLUE}[*] [{target_url}] Attempting active confirmation...{C.RESET}")
                    confirmed = stored_detector.confirm(probe_finding)
                    if confirmed:
                        print(f"    {C.RED}{C.BOLD}[!!!] [{target_url}] STORED XSS CONFIRMED{C.RESET}")
                        print(f"          Payload: {confirmed.payload.value}")
                        target_findings.append(confirmed)
                    else:
                        print(f"    {C.YELLOW}[-] [{target_url}] Active confirmation failed (Payload not found){C.RESET}")

    return target_findings


def main():
    print(f"{C.BLUE}{C.BOLD}XSS Tester v{VERSION}{C.RESET}")

    parser = argparse.ArgumentParser(description="Advanced XSS Detection Tool")
    parser.add_argument("target_url", nargs="?", help="The target URL to scan")
    parser.add_argument("-f", "--file", help="File containing list of URLs to scan")
    parser.add_argument("-c", "--concurrency", type=int, default=1, help="Number of concurrent scans")
    parser.add_argument("--confirm-stored", action="store_true", help="Enable active confirmation for Stored XSS")
    
    args = parser.parse_args()

    urls = []
    if args.target_url:
        urls.append(args.target_url)
    
    if args.file:
        try:
            with open(args.file, "r") as f:
                file_urls = [line.strip() for line in f if line.strip()]
                urls.extend(file_urls)
        except FileNotFoundError:
            print(f"{C.RED}[!] File not found: {args.file}{C.RESET}")
            sys.exit(1)

    if not urls:
        print(f"{C.RED}[!] No target specified. Provide a URL or a file with -f.{C.RESET}")
        parser.print_help()
        sys.exit(1)

    confirm_stored = args.confirm_stored
    if confirm_stored:
        print(f"[+] Stored XSS Active Confirmation: {C.GREEN}ENABLED{C.RESET}")

    # 3️⃣ Carregar payloads (un cop per a tots)
    payloads = load_payloads()

    all_findings = []
    
    print(f"[+] Starting scan of {len(urls)} targets with concurrency {args.concurrency}...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_to_url = {executor.submit(scan_target, url, confirm_stored, payloads): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
            except Exception as exc:
                print(f"{C.RED}[!] Exception scanning {url}: {exc}{C.RESET}")

    # Final Report
    print(f"\n{C.BLUE}{C.BOLD}[*] Final Report{C.RESET}")
    print(f"Total Targets: {len(urls)}")
    vulnerabilities = [f for f in all_findings if f.executed]
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    
    if vulnerabilities:
        print(f"\n{C.RED}Vulnerable Targets:{C.RESET}")
        for f in vulnerabilities:
            print(f" - {f.injection_point.url} ({f.injection_point.parameter}) -> {f.payload.value}")

if __name__ == "__main__":
    main()
