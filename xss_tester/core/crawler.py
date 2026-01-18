# core/crawler.py
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.visited = set()

    def crawl(self, url: str):
        if url in self.visited:
            return []

        self.visited.add(url)
        links = []

        r = httpx.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc == urlparse(self.base_url).netloc:
                links.append(link)

        return links
