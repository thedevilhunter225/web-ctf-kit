# PParse walkthrough: white-box analysis + reflected HTML + admin bot

A distributed "PParse"-style challenge with these security-relevant patterns:

1. `dist/templates/index.html`: `{{ parsed_output|safe }}` disables auto-escaping.
2. `dist/app.py`: a custom HTML tag blacklist drops many tags but leaves some
   attributes/handlers through.
3. `dist/bot.py`: a Selenium admin bot holds a secret cookie before visiting a
   reported page.
4. `dist/app.py`: `/report` accepts a URL on `127.0.0.1`/`localhost` and calls
   `bot.visit(url)`.

### 1. Analyze the source offline (no server needed)

```bash
webctf analyze --source ./dist.zip --output ./reports/pparse-source
```

Expect: *HTML autoescape bypass* (`|safe`), a *custom input filter* lead, the
*JavaScript-readable cookie* in the bot, and the detected framework.

### 2. Probe the live, authorized instance

```bash
webctf scan --url http://CTF_HOST:CTF_PORT/ \
    --ack-authorized --max-tests 40 --output ./reports/pparse-live
```

This finds the `html_input` form and reports whether a small
`<h1 autofocus ...>` / broken-tag canary is reflected unescaped (a
blacklist-bypass variant is highlighted when the simple tags are filtered).

### 3. Drive the admin bot (after confirming XSS in a browser)

```bash
webctf bot --url http://CTF_HOST:CTF_PORT/ \
    --report-path /report \
    --bot-base http://127.0.0.1:8000/ \
    --inject-param html_input \
    --payload-file ./examples/inert-xss.html \
    --ack-authorized --timeout 12
```

The helper builds the visit URL and submits it to the same-origin report
endpoint; it returns the HTTP status but **does not** itself prove the bot
executed the payload or exfiltrate anything. Browser confirmation (e.g. the
optional Playwright driver, `pip install web-ctf-kit[browser]`) is separate.

**Why not fully auto-solve every bot challenge?** Exploiting an admin bot usually
needs challenge-specific URL construction, cookie scope and browser behavior. The
kit automates the repeatable parts (detection, URL building, submission) so you
focus on the unique step.
