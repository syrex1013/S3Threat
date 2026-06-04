"""
Crawl a company website and extract S3 bucket name seeds from HTML, DOM, and JS.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser

UA = "S3Threat/1.0 (authorized-assessment)"
FETCH_TIMEOUT = 12
MAX_BODY = 2 * 1024 * 1024
DEFAULT_MAX_PAGES = 80

STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "com", "for", "from",
    "has", "have", "http", "https", "in", "is", "it", "its", "of", "on", "or",
    "our", "out", "over", "that", "the", "this", "to", "us", "was", "we", "web",
    "with", "www", "you", "your", "all", "can", "not", "but", "will", "new",
    "get", "set", "use", "true", "false", "null", "undefined", "var", "let",
    "function", "return", "class", "style", "div", "span", "html", "body",
    "head", "meta", "link", "script", "type", "text", "lang", "en", "de", "fr",
    "home", "page", "menu", "nav", "footer", "header", "main", "content",
    "click", "here", "more", "read", "view", "see", "one", "two", "may",
    "auto", "avoid", "background", "border", "color", "display", "flex",
    "font", "margin", "opacity", "padding", "position", "sans", "serif",
    "solid", "transparent", "inherit", "initial", "block", "inline", "none",
    "eee", "fff", "ccc", "ddd", "aaa", "rgb", "rgba", "url", "src", "href",
    "important", "hover", "focus", "active", "media", "screen", "print",
    "net", "org", "io", "co",
}

_TOKEN = re.compile(r"[a-z][a-z0-9]{2,24}")
_CSS_NOISE = re.compile(
    r"^(\d+(\.\d+)?(px|em|rem|vh|vw|vmin|vmax|%|pt|ch|ex)|auto|none|inherit|"
    r"initial|unset|solid|hidden|block|inline|flex|grid|center|left|right|"
    r"[0-9a-f]{3,8}|rgba?\(.*)$",
    re.I,
)
_CAMEL_SPLIT = re.compile(r"([a-z0-9])([A-Z])")
_S3_BUCKET = re.compile(
    r'(?i)(?:bucket|s3Bucket|s3_bucket|bucketName|bucket_name)'
    r'["\s:=]+["\']?([a-z0-9][a-z0-9.\-_]{2,62})',
)
_JSON_LD = re.compile(
    r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.I | re.S,
)
_INLINE_SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)


@dataclass
class ScrapeResult:
    url: str
    seeds: list[str] = field(default_factory=list)
    pages_crawled: int = 0
    tokens_seen: int = 0
    sources: dict = field(default_factory=dict)


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.meta: dict[str, str] = {}
        self.text_chunks: list[str] = []
        self.script_inline: list[str] = []
        self._in_script = False
        self._script_buf: list[str] = []
        self._skip = {"script", "style", "noscript"}

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and ad.get("href"):
            self.links.append(ad["href"])
        if tag == "meta":
            key = (ad.get("name") or ad.get("property") or "").lower()
            if key and ad.get("content"):
                self.meta[key] = ad["content"]
        if tag in ("h1", "h2", "h3", "title"):
            self._capture_tag = tag
        if tag == "script":
            self._in_script = True
            self._script_buf = []
            if ad.get("src"):
                self.script_inline.append(f"/* src={ad['src']} */")
        for attr in ("id", "class", "data-name", "data-product", "data-app"):
            if ad.get(attr):
                self.text_chunks.append(ad[attr].replace("-", " ").replace("_", " "))

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            self.script_inline.append("".join(self._script_buf))
            self._script_buf = []

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
        else:
            t = data.strip()
            if len(t) > 2:
                self.text_chunks.append(t)


def _fetch(url: str) -> tuple[str | None, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            ctype = resp.headers.get("Content-Type", "")
            if "text/html" not in ctype and "application/xhtml" not in ctype:
                return None, ctype
            return resp.read(MAX_BODY).decode("utf-8", errors="replace"), ""
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        return None, str(e)


def _normalize_url(base: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
        return None
    try:
        u = urllib.parse.urljoin(base, href)
        p = urllib.parse.urlparse(u)
        if p.scheme not in ("http", "https"):
            return None
        return urllib.parse.urlunparse((
            p.scheme, p.netloc.lower(), p.path or "/",
            "", "", "",
        ))
    except ValueError:
        return None


def _site_root(url: str) -> tuple[str, str]:
    p = urllib.parse.urlparse(url)
    if not p.netloc:
        raise ValueError(f"invalid URL: {url}")
    if not p.scheme:
        url = "https://" + url
        p = urllib.parse.urlparse(url)
    root = f"{p.scheme}://{p.netloc}"
    return url, root


def _same_site(url: str, root_netloc: str) -> bool:
    host = urllib.parse.urlparse(url).netloc.lower()
    return host == root_netloc or host.endswith("." + root_netloc)


def _split_camel(text: str) -> str:
    return _CAMEL_SPLIT.sub(r"\1 \2", text)


def _tokens_from_text(text: str) -> set[str]:
    text = _split_camel(text).lower()
    text = re.sub(r"[^a-z0-9\s.\-_]", " ", text)
    found = set()
    for part in re.split(r"[\s.\-_/]+", text):
        part = part.strip()
        if part in STOP_WORDS or len(part) < 3:
            continue
        if _CSS_NOISE.match(part) or part.isdigit():
            continue
        if not part.isalpha():
            continue
        found.add(part)
    found.update(_TOKEN.findall(text))
    return found


def _domain_seeds(root_url: str) -> set[str]:
    host = urllib.parse.urlparse(root_url).netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    seeds = {host.replace(".", "-"), host.replace(".", "")}
    labels = host.split(".")
    if labels:
        seeds.add(labels[0])
    if len(labels) >= 2:
        seeds.add(labels[0] + labels[1])
        seeds.add(f"{labels[0]}-{labels[1]}")
    return {s for s in seeds if 3 <= len(s) <= 63}


def _path_seeds(path: str) -> set[str]:
    out = set()
    for seg in path.split("/"):
        seg = re.sub(r"[^a-z0-9\-]", "", seg.lower())
        if 3 <= len(seg) <= 24 and seg not in STOP_WORDS:
            out.add(seg)
    return out


def _extract_from_html(html: str, page_url: str) -> tuple[set[str], list[str]]:
    tokens: set[str] = set()
    links: list[str] = []

    parser = _PageParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    links = parser.links
    for key in ("og:site_name", "og:title", "application-name", "twitter:title"):
        if key in parser.meta:
            tokens |= _tokens_from_text(parser.meta[key])
    for k, v in parser.meta.items():
        if "site" in k or "app" in k or "product" in k:
            tokens |= _tokens_from_text(v)

    tokens |= _tokens_from_text(" ".join(parser.text_chunks))

    for block in parser.script_inline:
        tokens |= _tokens_from_text(block)
        for m in _S3_BUCKET.finditer(block):
            tokens.add(m.group(1).lower().replace("_", "-"))

    for m in _JSON_LD.finditer(html):
        try:
            data = json.loads(m.group(1))
            tokens |= _tokens_from_json(data)
        except json.JSONDecodeError:
            pass

    for m in _INLINE_SCRIPT.finditer(html):
        block = m.group(1)
        if len(block) < 50000:
            tokens |= _tokens_from_text(block)
            for bm in _S3_BUCKET.finditer(block):
                tokens.add(bm.group(1).lower().replace("_", "-"))

    tokens |= _path_seeds(urllib.parse.urlparse(page_url).path)
    return tokens, links


def _tokens_from_json(obj) -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if any(x in kl for x in ("bucket", "s3", "storage", "cdn", "asset")):
                if isinstance(v, str):
                    out |= _tokens_from_text(v)
            out |= _tokens_from_json(v)
    elif isinstance(obj, list):
        for item in obj[:50]:
            out |= _tokens_from_json(item)
    elif isinstance(obj, str) and 3 <= len(obj) <= 40:
        out |= _tokens_from_text(obj)
    return out


def _clean_seeds(raw: set[str], valid_fn) -> list[str]:
    cleaned = set()
    for s in raw:
        s = s.lower().strip()
        s = re.sub(r"[^a-z0-9.\-]", "", s.replace("_", "-"))
        if not s or s in STOP_WORDS:
            continue
        if valid_fn(s):
            cleaned.add(s)
        elif len(s) > 63:
            for part in re.split(r"[\-.]", s):
                if valid_fn(part):
                    cleaned.add(part)
    return sorted(cleaned)


def _default_valid(name: str) -> bool:
    return (
        3 <= len(name) <= 63
        and re.fullmatch(r"[a-z0-9][a-z0-9.\-]*[a-z0-9]", name) is not None
        and ".." not in name
    )


def scrape_site(
    url: str,
    depth: int = 3,
    max_pages: int = DEFAULT_MAX_PAGES,
    valid_fn=None,
) -> ScrapeResult:
    """
    BFS crawl up to `depth` link hops from `url`; extract bucket seeds.
    """
    valid_fn = valid_fn or _default_valid

    start_url, root = _site_root(url)
    root_netloc = urllib.parse.urlparse(root).netloc
    result = ScrapeResult(url=start_url)
    all_tokens: set[str] = set()
    all_tokens |= _domain_seeds(root)

    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    visited: set[str] = set()

    while queue and result.pages_crawled < max_pages:
        page_url, d = queue.popleft()
        if page_url in visited or d > depth:
            continue
        visited.add(page_url)

        html, err = _fetch(page_url)
        if not html:
            continue
        result.pages_crawled += 1

        tokens, links = _extract_from_html(html, page_url)
        all_tokens |= tokens

        if d < depth:
            for href in links:
                nxt = _normalize_url(page_url, href)
                if nxt and nxt not in visited and _same_site(nxt, root_netloc):
                    queue.append((nxt, d + 1))

        time.sleep(0.15)

    result.tokens_seen = len(all_tokens)
    result.seeds = _clean_seeds(all_tokens, valid_fn)
    result.sources = {
        "domain": sorted(_domain_seeds(root)),
        "sample_tokens": sorted(all_tokens)[:40],
    }
    return result
