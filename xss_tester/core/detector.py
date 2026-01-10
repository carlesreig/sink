from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from .models import InjectionPoint, Form


class Detector:

    def detect(self, url: str, html: str):
        soup = BeautifulSoup(html, "html.parser")

        points: list[InjectionPoint] = []
        seen: set[tuple[str, str, str]] = set()

        # Helper per deduplicació
        def add_point(point: InjectionPoint):
            key = (
                point.method,
                point.url,
                point.parameter
            )
            if key not in seen:
                seen.add(key)
                points.append(point)

        # --------------------------------------------------
        # FORMS
        # --------------------------------------------------
        for form in soup.find_all("form"):
            action = form.get("action") or url
            action = urljoin(url, action)
            method = form.get("method", "get").upper()

            fields = {}
            injectable = []

            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue

                field_type = field.get("type", "").lower()
                value = field.get("value")

                fields[name] = value

                # Excloem botons i hidden
                if field_type not in ("submit", "button", "hidden"):
                    injectable.append(name)

            if not injectable:
                continue

            form_obj = Form(
                action=action,
                method=method,
                fields=fields,
                injectable_fields=injectable
            )

            for name in injectable:
                add_point(
                    InjectionPoint(
                        form=form_obj,
                        url=action,
                        method=method,
                        parameter=name,
                        source="form"
                    )
                )

        # --------------------------------------------------
        # URL PARAMETERS (GET)
        # --------------------------------------------------
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for param in params:
            add_point(
                InjectionPoint(
                    url=base_url,
                    method="GET",
                    parameter=param,
                    source="url_param"
                )
            )

        return points
