# config.py

# ---------- GENERAL ----------
# stored xss version
VERSION = "0.7.0"
# identificador unic per detectar reflexions
MARKER = "DPECE14"

REQUEST_TIMEOUT = 4

# ---------- PLAYWRIGHT ----------
PLAYWRIGHT = {
    "headless": True,
    "page_timeout": 10000,
    "post_load_wait": 2000
}

# ---------- SCORING ----------
RISK_SCORE = {
    "script": 7,
    "html_attribute": 5,
    "html_text": 4,
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
STOP_ON_FIRST_CONFIRMED = False
MAX_PAYLOADS_PER_POINT = 5
