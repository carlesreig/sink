from playwright.sync_api import Page


class TriggerRegistry:
    """
    Registre centralitzat de triggers basats en events JS
    """

    def __init__(self):
        self._triggers = {}

    def register(self, event: str, handler):
        self._triggers[event] = handler

    def run(self, page: Page, events: list[str]) -> bool:
        """
        Executa els triggers associats als events indicats.
        Retorna True si algun trigger provoca execució XSS.
        """
        for event in events:
            trigger = self._triggers.get(event)
            if not trigger:
                continue

            try:
                if trigger(page):
                    return True
            except Exception:
                continue

        return False
