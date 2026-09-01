"""简单同源爬虫：发现链接(GET)与表单(GET/POST)，产出 Target 列表。"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .models import Target


class _Parser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.host = urlsplit(base).netloc
        self.links = []
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a":
            href = d.get("href")
            if href:
                u = urljoin(self.base, href)
                if urlsplit(u).netloc == self.host and "#" not in u:
                    self.links.append(u)
        elif tag == "form":
            action = d.get("action") or self.base
            self._form = {
                "action": urljoin(self.base, action),
                "method": (d.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._form is not None:
            name = d.get("name")
            if name and d.get("type") != "submit":
                self._form["inputs"].append((name, d.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def discover(html: str, base: str) -> "_Parser":
    p = _Parser(base)
    p.feed(html)
    return p


def targets_from_html(html: str, base: str) -> list:
    """从页面 HTML 解析出所有待检测 Target（GET 链接 + 表单）。"""
    from .engine import Scanner
    p = discover(html, base)
    out = []
    seen = set()
    for link in p.links:
        for t in Scanner.extract_targets(link):
            key = (t.url, t.param, t.location)
            if key not in seen:
                seen.add(key); out.append(t)
    for f in p.forms:
        if not f["inputs"]:
            continue
        params = {k: v for k, v in f["inputs"]}
        if f["method"] == "POST":
            for k in params:
                key = (f["action"], k, "body")
                if key not in seen:
                    seen.add(key)
                    out.append(Target(url=f["action"], param=k, method="POST",
                                       original=params[k], body_params=params,
                                       location="body"))
        else:
            for k in params:
                key = (f["action"], k, "query")
                if key not in seen:
                    seen.add(key)
                    out.append(Target(url=f["action"], param=k, method="GET",
                                       original=params[k], params=params,
                                       location="query"))
    return out
