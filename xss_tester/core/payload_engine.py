from typing import List
from xss_tester.core.models import Payload, InjectionPoint


class PayloadEngine:
    """
    Selecciona payloads en funció del context detectat
    """

    def select(self, payloads: List[Payload], point: InjectionPoint) -> List[Payload]:
        selected = []

        for payload in payloads:
            if payload.expected_context and payload.expected_context != point.context:
                continue
            if payload.expected_subcontext and payload.expected_subcontext != point.subcontext:
                continue
            selected.append(payload)

        return selected

    def fallback(self, point: InjectionPoint) -> List[Payload]:
        """
        Payloads genèrics si no tenim context clar
        """
        return [
            Payload(value="<script>alert(1)</script>", category="xss"),
            Payload(value='"><svg/onload=alert(1)>', category="xss"),
            Payload(value="<img src=x onerror=alert(1)>", category="xss"),
        ]
