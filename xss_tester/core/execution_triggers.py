from playwright.sync_api import Page
from xss_tester.core.models import InjectionPoint
import time


class ExecutionTriggerEngine:
    """
    Execution Trigger Engine

    - Reutilitza TOTS els triggers existents
    - Evita deadlocks de Playwright
    - No perd funcionalitats
    - Preparat per discovery/requires
    """

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------
    def try_triggers(
        self,
        page: Page,
        injection_point: InjectionPoint,
        payload=None
    ) -> bool:
        """
        Try all known execution triggers.
        """

        triggers = [
            self._trigger_focus_blur,
            self._trigger_mouse_events,
            self._trigger_keyboard_events,
            self._trigger_change_submit,
            self._trigger_click_generic,
            self._trigger_timers,
        ]

        for trigger in triggers:
            try:
                if trigger(page, injection_point, payload):
                    return True
            except Exception:
                # NEVER let a trigger break execution
                continue

        return False

    # ----------------------------------------------------------
    # Triggers
    # ----------------------------------------------------------
    def _execute_js_trigger(self, page, script: str) -> bool:
        """Helper per executar JS de forma segura i comprovar XSS"""
        try:
            page.evaluate(script)
            return self._post_trigger_check(page)
        except Exception:
            return False

    def _trigger_focus_blur(self, page, point, payload=None) -> bool:
        return self._execute_js_trigger(page, """
                () => {
                    document.querySelectorAll(
                        'input, textarea, select, [contenteditable]'
                    ).forEach(el => {
                        try {
                            el.focus();
                            el.blur();
                        } catch(e) {}
                    });
                }
            """)

    def _trigger_mouse_events(self, page, point, payload=None) -> bool:
        return self._execute_js_trigger(page, """
                () => {
                    const events = [
                        'mouseover', 'mouseenter',
                        'mousemove', 'mousedown',
                        'mouseup', 'mouseout'
                    ];

                    document.querySelectorAll('*').forEach(el => {
                        events.forEach(evt => {
                            try {
                                el.dispatchEvent(
                                    new Event(evt, { bubbles: true })
                                );
                            } catch(e) {}
                        });
                    });
                }
            """)

    def _trigger_keyboard_events(self, page, point, payload=None) -> bool:
        return self._execute_js_trigger(page, """
                () => {
                    const events = ['keydown', 'keyup', 'keypress'];

                    document.querySelectorAll(
                        'input, textarea, [contenteditable]'
                    ).forEach(el => {
                        events.forEach(evt => {
                            try {
                                el.dispatchEvent(
                                    new Event(evt, { bubbles: true })
                                );
                            } catch(e) {}
                        });
                    });
                }
            """)

    def _trigger_change_submit(self, page, point, payload=None) -> bool:
        return self._execute_js_trigger(page, """
                () => {
                    document.querySelectorAll(
                        'input, textarea, select'
                    ).forEach(el => {
                        try {
                            el.dispatchEvent(
                                new Event('change', { bubbles: true })
                            );
                            el.dispatchEvent(
                                new Event('input', { bubbles: true })
                            );
                        } catch(e) {}
                    });

                    document.querySelectorAll('form').forEach(form => {
                        try {
                            form.dispatchEvent(
                                new Event('submit', { bubbles: true })
                            );
                        } catch(e) {}
                    });
                }
            """)

    def _trigger_click_generic(self, page, point, payload=None) -> bool:
        """
        FIXED VERSION:
        - evita bloquejos de navegació
        - no espera indefinidament
        """
        try:
            elements = page.query_selector_all(
                "a, button, input[type=button], input[type=submit]"
            )

            for el in elements:
                try:
                    # Navigation-safe click
                    try:
                        with page.expect_navigation(timeout=500):
                            el.click(timeout=300)
                    except Exception:
                        # No navigation expected → OK
                        try:
                            el.click(timeout=300)
                        except Exception:
                            pass

                    if self._post_trigger_check(page):
                        return True

                except Exception:
                    continue

            return False

        except Exception:
            return False

    def _trigger_timers(self, page, point, payload=None) -> bool:
        return self._execute_js_trigger(page, """
                () => {
                    try {
                        setTimeout(() => {}, 10);
                        setInterval(() => {}, 10);
                    } catch(e) {}
                }
            """)

    # ----------------------------------------------------------
    # Shared helpers
    # ----------------------------------------------------------
    def _post_trigger_check(self, page) -> bool:
        """
        Short wait + execution check
        """
        time.sleep(0.25)
        return self._check_execution(page)

    def _check_execution(self, page) -> bool:
        try:
            state = page.evaluate("window.__xss")
            return bool(state and state.get("triggered"))
        except Exception:
            return False
