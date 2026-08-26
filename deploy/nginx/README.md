# The Workspace vhost

`workspace.conf.template` is the **source** for the nginx site in front of this
plane. Until 2026-08-26 that config existed only on the host, which meant the
TLS terminator, the proxy headers that decide whether cookies carry `Secure`,
and two security headers were all unreviewable and one `rsync` away from being
lost. The compose file had already been bitten by exactly that: production
config lived hand-edited on the host until a deploy silently reverted it and
took the service down.

## Render

```sh
make nginx-render > /tmp/workspace.conf
```

Or directly — note that `envsubst` is **restricted to the two placeholders**.
Unrestricted, it also substitutes nginx's own `$host`, `$scheme`, `$remote_addr`
and `$proxy_add_x_forwarded_for`, producing a config that proxies with empty
headers and takes `Secure` off every cookie:

```sh
WORKSPACE_PUBLIC_HOST=workspace.dotmac.io \
WORKSPACE_UPSTREAM=http://127.0.0.1:8000 \
envsubst '${WORKSPACE_PUBLIC_HOST} ${WORKSPACE_UPSTREAM}' \
  < deploy/nginx/workspace.conf.template
```

## Check for drift

```sh
make nginx-diff
```

Renders the template and diffs it against the deployed file over SSH. Empty
output means the host matches this repository. This is the half that makes
tracking worth anything: a source of truth nobody compares is just a second
copy.

## Install

```sh
make nginx-render > /tmp/workspace.conf
scp /tmp/workspace.conf root@workspace.dotmac.io:/etc/nginx/sites-available/workspace.dotmac.io
ssh root@workspace.dotmac.io 'nginx -t && systemctl reload nginx'
```

`nginx -t` before the reload is not optional — a bad config that reloads takes
the site down, and `reload` will refuse rather than half-apply.

Then verify **from outside**, not from "nginx is active":

```sh
curl -sSI https://workspace.dotmac.io/ | grep -iE 'strict-transport|referrer-policy|set-cookie'
```

Expect one `Strict-Transport-Security`, `Secure` on the cookie, and two
`Referrer-Policy` values whose last is `no-referrer` — see the template's
comments for why that duplication is deliberate.

## What this file does not own

The certificate. `certbot` issues it and this vhost only points at the result,
which is why there are no `# managed by Certbot` markers to preserve. Renewal is
unaffected by re-installing this file.
