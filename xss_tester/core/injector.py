import httpx
from xss_tester.core.models import InjectionPoint, Payload
from xss_tester.config import REQUEST_TIMEOUT


class Injector:
    """
    Responsable de fer les peticions HTTP amb payloads injectats
    """

    def __init__(self, client: httpx.Client = None):
        self.client = client

    def _request(self, method: str, url: str, **kwargs):
        """Helper centralitzat per fer peticions HTTP uniformes"""
        if self.client:
            return self.client.request(
                method,
                url,
                follow_redirects=True,
                **kwargs
            )

        return httpx.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            **kwargs
        )

    def inject(self, point: InjectionPoint, payload: Payload):

        # Gestió de fragments (client-side injection)
        if point.source == "fragment":
            return self._request("GET", f"{point.url}#{payload.value}")

        if point.source == "fragment_query":
            return self._request("GET", f"{point.url}?{point.parameter}={payload.value}")

        if point.form:
            data = dict(point.form.fields)
            data[point.parameter] = payload.value

            if point.form.method == "GET":
                return self._request("GET", point.form.action, params=data)

            if point.form.method == "POST":
                return self._request("POST", point.form.action, data=data)

        # fallback (URL params)
        params_or_data = {point.parameter: payload.value}

        if point.method == "GET":
            return self._request("GET", point.url, params=params_or_data)

        if point.method == "POST":
            return self._request("POST", point.url, data=params_or_data)

        raise ValueError(f"Unsupported HTTP method: {point.method}")
