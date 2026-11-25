#!/usr/bin/env bash
# Regenerates the README screenshots in docs/images from warden-demo.
#
#   scripts/screenshots.sh            # needs go, python3 and firefox
#
# Headless Firefox captures at the load event, before a page's fetches have
# rendered. A tiny proxy in front of the demo appends a hidden image that
# answers after 3s, which holds the load event until the data is drawn.
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO=127.0.0.1:8781 PROXY=8782 OUT=docs/images
tmp=$(mktemp -d)
cleanup() { kill "${demo_pid:-}" "${proxy_pid:-}" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

go build -o "$tmp/warden-demo" ./cmd/warden-demo
"$tmp/warden-demo" -addr "$DEMO" & demo_pid=$!

cat >"$tmp/proxy.py" <<'PY'
import http.server, sys, time, urllib.request
up, port = "http://" + sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/__hold"):
            time.sleep(3); self.send_response(404); self.end_headers(); return
        with urllib.request.urlopen(up + self.path) as r:
            body, ct = r.read(), r.headers.get("Content-Type", "")
        if ct.startswith("text/html"):
            body = body.replace(b"</body>", b'<img src="/__hold" style="display:none"></body>')
        self.send_response(200); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 -I "$tmp/proxy.py" "$DEMO" "$PROXY" & proxy_pid=$!

for _ in $(seq 60); do curl -sf "http://$DEMO/health" >/dev/null && break; sleep 0.5; done
# The seeded alert investigation (the one with a diagnosis).
inv=$(curl -sf "http://$DEMO/console/api/investigations" |
  python3 -Ic 'import json,sys; print(next(r["id"] for r in json.load(sys.stdin) if r.get("diagnosed")))')

shot() { # name height path
  firefox --headless --no-remote --profile "$tmp/profile" \
    --window-size="1440,$2" --screenshot "$PWD/$OUT/$1.png" "http://127.0.0.1:$PROXY$3" >/dev/null 2>&1
  echo "$OUT/$1.png"
}
mkdir -p "$tmp/profile" "$OUT"
shot map           900  "/map"
shot services      963  "/services#range=24h&open=linkding"
shot console       560  "/console#/"
shot investigation 1205 "/console#/inv/$inv"
shot namespace     1600 "/console#/ns/linkding"
