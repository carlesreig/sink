# ---------- GENERAL ----------
# evitar WAFs
VERSION = "0.7.2"
# identificador unic per detectar reflexions
MARKER = "DPECE14"

REQUEST_TIMEOUT = 4

# ---------- HTTP HEADERS (WAF Bypass) ----------
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# ---------- PLAYWRIGHT ----------
PLAYWRIGHT = {
    "headless": True,
    "page_timeout": 10000,
    "post_load_wait": 2000,
}

# ---------- SCORING ----------
RISK_SCORE = {
    "script": 7,
    "attribute": 5,
    "html": 4,
    "comment": 1,
    "encoded": 2,
    "unknown": 1,

    "js_eval": 9,
    "event_handler": 8,

    # DOM-XSS
    "dom": 8,
    "dom_sink": 9,
}

# ---------- ENGINE ----------
STOP_ON_FIRST_CONFIRMED = True
MAX_PAYLOADS_PER_POINT = 5
