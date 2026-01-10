import httpx
from xss_tester.core.models import InjectionPoint, Payload
from xss_tester.config import REQUEST_TIMEOUT


class Injector:
    """
    Responsable de fer les peticions HTTP amb payloads injectats
    """

    def inject(self, point: InjectionPoint, payload: Payload):

        if point.form:
            data = dict(point.form.fields)
            data[point.parameter] = payload.value

            if point.form.method == "GET":
                return httpx.get(
                    point.form.action,
                    params=data,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True
                )

            if point.form.method == "POST":
                return httpx.post(
                    point.form.action,
                    data=data,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True
                )

        # fallback (URL params)
        if point.method == "GET":
            return httpx.get(
                point.url,
                params={point.parameter: payload.value},
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True
            )

        if point.method == "POST":
            return httpx.post(
                point.url,
                data={point.parameter: payload.value},
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True
            )

        raise ValueError(f"Unsupported HTTP method: {point.method}")
