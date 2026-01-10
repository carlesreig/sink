from playwright.sync_api import Page


class DOMDiscovery:
    """
    Passive DOM discovery.
    NO execution, NO triggers.
    """

    def run(self, page: Page) -> list[str]:
        """
        Returns a list of discovered DOM features.
        """

        return page.evaluate("""
            () => {
                const features = new Set();

                // --------------------------------
                // Discover on* attributes
                // --------------------------------
                document.querySelectorAll('*').forEach(el => {
                    for (const attr of el.getAttributeNames()) {
                        if (attr.startsWith('on')) {
                            features.add('event:*');

                            if (attr === 'ontoggle') features.add('event:toggle');
                            if (attr === 'onmouseover') features.add('event:hover');
                            if (attr === 'onfocus') features.add('event:focus');
                            if (attr.startsWith('onanimation'))
                                features.add('event:animation');
                        }
                    }
                });

                // --------------------------------
                // Structural elements
                // --------------------------------
                if (document.querySelector('details'))
                    features.add('element:details');

                // --------------------------------
                // Interactive surfaces
                // --------------------------------
                if (document.querySelector(
                    'a, button, input[type=submit], input[type=button]'
                )) {
                    features.add('interaction:click');
                }

                if (document.querySelector(
                    'input, textarea, select, [contenteditable]'
                )) {
                    features.add('interaction:focus');
                }

                return Array.from(features);
            }
        """)
