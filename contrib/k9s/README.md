# Warden in k9s

Two shortcuts that bring Warden's evidence into k9s
([Homelab ADR 0011, amendment 2026-11-25](https://github.com/Blacklotus89898/Homelab/blob/main/docs/adr/0011-warden-sre-agent.md)):

| Key | On | Does |
|---|---|---|
| `Shift-W` | pod, namespace | opens the console for the namespace: what changed, traffic, blast radius |
| `Shift-I` | pod, namespace, node | asks first, then runs "investigate now" and opens the investigation |

This is a client. Warden never gets your kubeconfig and k9s never gets Warden's
service account: Warden reads the cluster, and whatever you do next in k9s is
you, with your own credentials. Start k9s with `--readonly` when you are only
looking.

## Install

```sh
install -m 755 contrib/k9s/warden-k9s ~/.local/bin/   # anywhere on PATH
k9s info                                              # shows where plugins.yaml lives
# merge contrib/k9s/plugins.yaml into that file
```

Needs `sh` and `curl` (on Windows, Git Bash's). Set `WARDEN_CACERT` to the
Homelab Root CA if `*.lab.home` isn't trusted by the system.

`Shift-W` works as is: it opens the browser, which signs in to authentik the
usual way.

`Shift-I` calls the API from the terminal, so it needs an authentik **app
password** (one per machine, with an expiry):

1. In authentik, on provider `warden-console`, turn on **Intercept header
   authentication** (Advanced protocol settings). Leave it off on every other
   provider.
2. User settings → Tokens and App passwords → create an app password.
3. Store it and check it:

   ```sh
   mkdir -p ~/.config/warden && umask 077
   printf '%s:%s\n' "<authentik user>" "<app password>" > ~/.config/warden/credentials
   warden-k9s whoami        # {"user":"<you>",...}
   ```

Revoke a machine by deleting its token in authentik.

## Limits

The same as the console's "investigate now": journal only (no phone push), one
at a time and at least 10s apart, a daily bound, and refused while
`WARDEN_ENABLED=false`.
