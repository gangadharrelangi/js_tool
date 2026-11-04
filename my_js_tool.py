#!/usr/bin/env python3
"""Fetch JavaScript into memory and scan for endpoints and potential secrets."""
import argparse
from collections import deque
from html.parser import HTMLParser
import json
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlsplit
from urllib.request import Request

from patterns import LINK_PATTERN, SECRET_PATTERNS

SECRETS = {name: re.compile(pattern, re.VERBOSE | re.I)
           for name, pattern in SECRET_PATTERNS.items()}
SECRETS.update({
    'github_token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b'),
    'github_fine_grained': re.compile(r'\bgithub_pat_[A-Za-z0-9_]{30,}\b'),
    'jwt': re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
})
IMPORTS = re.compile(
    r'''(?:\b(?:import|export)\s+(?:[^;\n]*?\s+from\s*)?|\b(?:import|require|importScripts)\s*\(\s*)["']([^"']+)["']''')
JS_SUFFIX = re.compile(r'\.(?:m?js|cjs)$', re.I)


def http_url(value):
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('Expected an absolute http:// or https:// URL')
    return urldefrag(value)[0]


def origin(url):
    p = urlsplit(url)
    return p.scheme.lower(), p.hostname, p.port or (443 if p.scheme == 'https' else 80)


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources, self.inline = [], []
        self.base = None
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'base' and self.base is None:
            self.base = attrs.get('href')
        if tag == 'script':
            if attrs.get('src'):
                self.sources.append(attrs['src'])
            kind = attrs.get('type', '').lower().split(';')[0]
            self.current = [] if not attrs.get('src') and kind in (
                '', 'module', 'text/javascript', 'application/javascript',
                'text/ecmascript', 'application/ecmascript') else None
        if tag == 'link' and (attrs.get('rel') == 'modulepreload' or
                              attrs.get('as') == 'script') and attrs.get('href'):
            self.sources.append(attrs['href'])

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.current is not None:
            self.inline.append(''.join(self.current))
            self.current = None


def findings(source, text):
    links, secrets = [], []
    seen = set()
    for match in LINK_PATTERN.finditer(text):
        value = match.group(1)
        if value not in seen:
            seen.add(value)
            links.append({'value': value, 'line': text.count('\n', 0, match.start()) + 1})
    for name, pattern in SECRETS.items():
        seen = set()
        for match in pattern.finditer(text):
            value = match.group(0)
            if value not in seen:
                seen.add(value)
                secrets.append({'type': name, 'value': value,
                                'line': text.count('\n', 0, match.start()) + 1})
    return {'source': source, 'endpoints': links, 'potential_secrets': secrets}


def dependencies(text):
    for match in IMPORTS.finditer(text):
        value = match.group(1)
        # Bare package names require a module resolver/import map.
        if value.startswith(('/', './', '../', 'http://', 'https://')):
            yield value
    for match in LINK_PATTERN.finditer(text):
        value = match.group(1)
        if JS_SUFFIX.search(urlsplit(value).path):
            yield value


def scan(url, *, timeout=15, max_files=100, max_bytes=10 * 1024 * 1024,
         include_external=False):
    url = http_url(url)
    allowed_origin = origin(url)
    queue, scheduled, fetched = deque([url]), {url}, set()
    report = {'input': url, 'results': [], 'errors': [], 'skipped': [],
              'truncated': False}

    def enqueue(base, value):
        try:
            target = http_url(urljoin(base, value))
            if not include_external and origin(target) != allowed_origin:
                if target not in scheduled:
                    report['skipped'].append({'url': target, 'reason': 'external origin'})
                    scheduled.add(target)
                return
            if target not in scheduled:
                scheduled.add(target)
                queue.append(target)
        except ValueError:
            return

    def process(source, content, base):
        report['results'].append(findings(source, content))
        for value in dependencies(content):
            enqueue(base, value)

    # Validate every redirect before urllib follows it, including cross-origin ones.
    from urllib.request import HTTPRedirectHandler, build_opener

    class RedirectPolicy(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            target = http_url(newurl)
            if not include_external and origin(target) != allowed_origin:
                raise ValueError('Redirect to external origin blocked: ' + target)
            return super().redirect_request(req, fp, code, msg, headers, target)

    opener = build_opener(RedirectPolicy())
    attempts = 0
    while queue and attempts < max_files:
        target = queue.popleft()
        if target in fetched:
            continue
        attempts += 1
        try:
            request = Request(target, headers={'User-Agent': 'my_js_tool/1.0',
                                               'Accept-Encoding': 'identity'})
            with opener.open(request, timeout=timeout) as response:
                final_url = http_url(response.url)
                if final_url in fetched:
                    continue
                fetched.update((target, final_url))
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise ValueError(f'Response exceeds {max_bytes} bytes')
                if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                    raise ValueError('Unsupported compressed response despite Accept-Encoding: identity')
                content = data.decode(response.headers.get_content_charset() or 'utf-8', 'replace')
                mime = response.headers.get_content_type()
            is_html = mime in ('text/html', 'application/xhtml+xml') or (
                not JS_SUFFIX.search(urlsplit(final_url).path) and
                content.lstrip().lower().startswith(('<!doctype html', '<html')))
            if is_html:
                parser = Scripts()
                parser.feed(content)
                base = urljoin(final_url, parser.base) if parser.base else final_url
                for src in parser.sources:
                    enqueue(base, src)
                for number, inline in enumerate(parser.inline, 1):
                    process(f'{final_url}#inline-{number}', inline, base)
            else:
                process(final_url, content, final_url)
        except (OSError, ValueError, HTTPError, URLError, LookupError) as exc:
            report['errors'].append({'url': target, 'error': str(exc)})
            if isinstance(exc, HTTPError):
                exc.close()
    report['truncated'] = bool(queue)
    report['requests_attempted'] = attempts
    return report


def positive_int(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError('must be greater than zero')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url', nargs='?', help='Page URL or direct JavaScript URL')
    parser.add_argument('-i', '--input', help='Alternative to positional URL')
    parser.add_argument('--include-external', action='store_true', help='Also fetch scripts on other origins/CDNs')
    parser.add_argument('--max-files', type=positive_int, default=100, help='Maximum HTTP fetches (default: 100)')
    parser.add_argument('--max-bytes', type=positive_int, default=10 * 1024 * 1024, help='Maximum bytes per response')
    parser.add_argument('--timeout', type=positive_int, default=15, help='Socket timeout in seconds')
    parser.add_argument('--json', action='store_true', help='Print JSON to stdout')
    args = parser.parse_args()
    if bool(args.url) == bool(args.input):
        parser.error('Provide exactly one URL, positional or -i')
    try:
        report = scan(args.url or args.input, timeout=args.timeout, max_files=args.max_files,
                      max_bytes=args.max_bytes, include_external=args.include_external)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for item in report['results']:
            print('\n' + item['source'])
            for link in item['endpoints']:
                print(f"  endpoint L{link['line']}: {link['value']}")
            for secret in item['potential_secrets']:
                print(f"  potential secret [{secret['type']}] L{secret['line']}: {secret['value']}")
        for error in report['errors']:
            print(f"ERROR {error['url']}: {error['error']}", file=sys.stderr)
        print(f"\nScanned {len(report['results'])} script blocks/files; "
              f"{len(report['errors'])} errors; {len(report['skipped'])} external URLs skipped.")
        if report['truncated']:
            print('File limit reached; results are incomplete. Increase --max-files.')
    return 1 if report['errors'] or report['truncated'] else 0


if __name__ == '__main__':
    sys.exit(main())
