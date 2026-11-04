# my_js_tool

Combines the local LinkFinder endpoint patterns and SecretFinder secret patterns
in a standalone URL scanner. Requires Python 3.9+ and only the standard library;
no pip installation is necessary. Original tools are left intact.

```sh
python3 my_js_tool.py https://example.com
python3 my_js_tool.py -i https://example.com/assets/app.js
python3 my_js_tool.py https://example.com --include-external
python3 my_js_tool.py https://example.com --json > results.json
```

HTTP response bodies are fetched into memory, scanned, and discarded. JavaScript
source files are never saved. Reports go to stdout; redirecting output saves only
the report. Python may create its ordinary bytecode cache; use `python3 -B` to
suppress that if desired.

For a page URL the scanner reads script src attributes, inline JavaScript, script
preloads, and the HTML base URL. It recursively follows discoverable quoted JS
references and literal imports (including extensionless relative module imports).
A direct JS URL is scanned immediately with the same recursive discovery. Each
result includes its source URL and line numbers in the original response (inline
line numbers are relative to that script block). TLS certificates are verified.

By default only the input URL's origin is fetched, including for redirects. Use
`--include-external` to include CDN/other-origin scripts and redirects. A redirect
from example.com to www.example.com also needs this flag, or supply the final URL.
External URLs skipped by the default policy are recorded in JSON. This scans
scripts, not all linked HTML pages on the site.

Limits: `--max-files 100` counts HTTP fetch attempts (redirects follow urllib's
separate redirect limit), `--max-bytes 10485760` limits each response, and
`--timeout 15` sets the socket timeout. Fetch errors and file-limit truncation
produce exit status 1 and remain in the report; successful scans return 0.
Invalid command-line arguments return 2. Compressed responses are rejected if a
server ignores the identity encoding request.

This is static discovery: it cannot guarantee finding all JavaScript. It does
not execute browser code, interact with pages, resolve import maps/bare package
names, enumerate bundler-generated chunk names, or fetch source maps. Supply
runtime-only script URLs separately. Secret matches are candidates that need
review; matches are printed unredacted, so handle reports as sensitive data.

Run the local HTTP integration tests:

```sh
python3 -B -m unittest -v
```

See NOTICE, LICENSE (GPL-3.0), and licenses/ for upstream attribution and terms.
# js_tool
