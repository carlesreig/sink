from playwright.sync_api import Page


# --------------------------------------------------
# <details ontoggle=...>
# --------------------------------------------------
def trigger_ontoggle(page: Page) -> bool:
    page.evaluate("""
        () => {
            document.querySelectorAll("details").forEach(d => {
                try {
                    d.open = false;
                    d.open = true;
                } catch(e) {}
            });
        }
    """)
    page.wait_for_timeout(300)
    return page.evaluate("window.__xss && window.__xss.triggered === true")


# --------------------------------------------------
# onmouseover
# --------------------------------------------------
def trigger_onmouseover(page: Page) -> bool:
    page.evaluate("""
        () => {
            document.querySelectorAll("*").forEach(el => {
                try {
                    el.dispatchEvent(
                        new MouseEvent("mouseover", { bubbles: true })
                    );
                } catch(e) {}
            });
        }
    """)
    page.wait_for_timeout(300)
    return page.evaluate("window.__xss && window.__xss.triggered === true")


# --------------------------------------------------
# onfocus
# --------------------------------------------------
def trigger_onfocus(page: Page) -> bool:
    page.evaluate("""
        () => {
            document.querySelectorAll("input, textarea, select, button, a").forEach(el => {
                try {
                    el.focus();
                } catch(e) {}
            });
        }
    """)
    page.wait_for_timeout(300)
    return page.evaluate("window.__xss && window.__xss.triggered === true")
