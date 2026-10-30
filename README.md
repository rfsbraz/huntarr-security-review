# Huntarr Security Reproduction Lab

Automated proof that Huntarr v9.4.2 has critical authentication bypass vulnerabilities. Every API endpoint tested below is callable by an unauthenticated attacker with zero credentials.

Full write-up: https://rodrigobraz.com/writing/huntarr-review/

**If you run Huntarr and it's reachable on your network, anyone can read your passwords and rewrite your config right now. No login required. This includes not just Huntarr's own credentials but API keys for every *arr application it manages - Sonarr, Radarr, Prowlarr, Lidarr, and more. If your instance is internet-facing (and Huntarr incorporates features like Requestarr that are designed for external access), a single unauthenticated curl command gives an attacker direct API access to your entire media stack.**

## The short version

Run one `curl` command against a stock Huntarr install with no cookies, no tokens, no auth of any kind:

```
curl -X POST http://your-huntarr:9705/api/settings/general \
  -H "Content-Type: application/json" \
  -d '{"proxy_enabled": true}'
```

The server happily accepts the write and returns your **entire configuration** in the response - not just the general section you wrote to, but config for every integrated application. The response includes fields like:

```json
"proxy_password": "your_actual_password_in_cleartext",
"proxy_username": "your_actual_username",
"dev_key": "...",
"prowlarr": { "api_key": "...", "api_url": "..." },
"sonarr": { "instances": [{ "api_key": "...", "url": "..." }] },
"radarr": { "instances": [{ "api_key": "...", "url": "..." }] }
```

No login page. No session cookie. No API key. Nothing. The endpoint is wide open, and it dumps credentials for your entire stack.

## Findings

Tested against `ghcr.io/plexguide/huntarr:latest` (v9.4.2, commit `fa475ab6`). That image can no longer be pulled, so the lab now builds v9.4.2 from the same commit in the public archive [MGHazz/huntarr.io-archive](https://github.com/MGHazz/huntarr.io-archive/tree/fa475ab683d1a1e1bf5d3b72d0ae1468a3a6c19e). No Huntarr source is copied into this repo.

| ID | Vulnerability | Severity | Result |
|----|--------------|----------|--------|
| T1 | Unauthenticated settings write + secrets leaked in response | Critical | **PASS** |
| T2 | Unauthenticated Plex account unlink | High | **PASS** |
| T3 | Client-controlled `setup_mode` bypasses auth on Plex link | High | **PASS** |
| T4 | Chained: unauth settings write + `X-Forwarded-For` spoof bypasses login | High | FAIL |
| T5 | Full cross-app credential exposure (Sonarr/Radarr/Prowlarr keys) | Critical | **PASS** |
| T6 | Unauthenticated 2FA setup returns TOTP secret | Critical | **PASS** |
| T7 | Unauthenticated recovery key generation via `setup_mode` | Critical | **PASS** |
| T8 | Unauthenticated setup clear re-arms account creation | Critical | **PASS** |

"PASS" means the vulnerability was confirmed. T4 did not reproduce in CI (the `local_access_bypass` setting change may require a middleware restart to take effect in the container).

### What this means

- **T1**: Anyone on your network can `POST /api/settings/general` without logging in. The server accepts arbitrary config changes and returns **every setting in the response**, including `proxy_password`, `proxy_username`, API keys, and integration credentials - all in cleartext. This is not a read-only leak; the attacker is also rewriting your configuration.
- **T2**: Anyone can `POST /api/auth/plex/unlink` and disconnect your Plex account from Huntarr. No session, no auth check.
- **T3**: Sending `{"setup_mode": true}` in the Plex link request skips session checks entirely. The server rejects the *token*, not the *caller* - meaning auth is never enforced on the endpoint.
- **T4**: Attempted to chain T1's unauth settings write (enable `local_access_bypass`) with `X-Forwarded-For: 127.0.0.1` spoofing. The settings write succeeded but the bypass didn't propagate within the test window. The vulnerability exists in code but may require a service restart to activate.
- **T5**: Writing a single innocuous setting (e.g., `timezone`) returns configuration for **every integrated *arr application** - Sonarr, Radarr, Prowlarr, Lidarr, etc. One unauthenticated call exfiltrates API keys for your entire media stack, not just Huntarr's own secrets.
- **T6**: `POST /api/user/2fa/setup` with no session returned the actual TOTP secret (`CYMC4RRRARVIKCRVMBUY777SQULOLGNL`) and a QR code for the owner account. An attacker generates a valid code, calls `/api/user/2fa/verify`, and enrolls their own authenticator. Full account takeover without knowing the password.
- **T7**: `POST /auth/recovery-key/generate` with `{"setup_mode": true}` reaches business logic without any auth check (returns 400 "Setup not properly initialized" rather than 401/403). The endpoint is unauthenticated; the specific exploit requires setup state alignment.
- **T8**: `POST /api/setup/clear` with no auth returned 200 "Setup progress cleared". The endpoint is fully unauthenticated and clears the setup state, which is a precondition for re-creating the owner account.

### Additional findings from source review (not yet in automated proofs)

The full review found **21 total findings**. Beyond the automated proofs above:

- **Zip Slip in backup upload** (High): `zipfile.extractall()` on user-uploaded ZIPs without filename sanitization. Crafted ZIPs can write files anywhere in the container (which runs as root).
- **Path traversal in backup restore/delete** (High): `backup_id` from user input is concatenated into filesystem paths with no sanitization. `shutil.rmtree()` makes this a directory deletion primitive.
- **Overly broad auth whitelist patterns** (High): The bypass uses substring matching (`'/api/user/2fa/' in request.path`) and suffix matching (`endswith('/setup')`, `endswith('/user')`) instead of exact route checks, exempting more endpoints than intended.

## How this was found

This took a basic code review and standard automated security tooling (`bandit`, `pip-audit`) - the kind of checks any maintainer should be running as part of normal development. No fuzzing, no reverse engineering, no exotic techniques. These are the basics.

The maintainer [claims](https://i.imgur.com/sjPAT1u.png) to have "a series of steering documents I generated that does cybersecurity checks and provides additional hardening" and says **"Note I also work in cybersecurity."** They also [claim](https://i.imgur.com/8AkHZ27.png) to have invested "120+ hours in the last 4 weeks" using "steering documents to advise along the way from cybersecurity, to hardening, and standards."

Despite working in cybersecurity and using cybersecurity-focused steering documents, `POST /api/settings/general` has zero authentication - not a broken check, not a misconfigured middleware, just no check at all. The auth bypass list in [`auth.py:525`](https://github.com/plexguide/Huntarr.io/blob/fa475ab6/src/primary/auth.py#L525) explicitly skips it. The 2FA setup endpoint returns the TOTP secret to unauthenticated callers. The setup clear endpoint lets anyone re-arm account creation. Running `bandit` on the source would have flagged the hardcoded credentials. Running any HTTP integration test against any of these endpoints without a session cookie would have caught the rest.

These are not subtle bugs. They are missing fundamentals - from someone who says they work in cybersecurity. The maintainer also [removes security reports](https://www.reddit.com/r/huntarr/comments/1rbtri7/removed_by_moderator/) from r/huntarr (which they moderate) and bans users who raise these concerns.

## Run It Yourself

Build the v9.4.2 lab image from the archived source, then start Huntarr and run the proof script:

```bash
git clone https://github.com/MGHazz/huntarr.io-archive.git huntarr-src
git -C huntarr-src checkout fa475ab683d1a1e1bf5d3b72d0ae1468a3a6c19e
docker build -t huntarr-lab:9.4.2 huntarr-src
docker compose up -d huntarr
python3 scripts/prove_vulns.py
```

Results are written to `results/proof-results.json` and `results/proof-results.md`.

To tear down:

```bash
docker compose down
```

Requires: Docker, Python 3.8+ (stdlib only, no pip installs).

## CI

This repo runs the proof automatically via GitHub Actions on every push. The workflow builds the lab image from the archive at the pinned commit first. If the archive is ever unreachable, the run fails with a message saying so, and the committed `results/` stand as the record. Check the [Actions tab](../../actions) for the latest run and download the `proof-results` artifact.

## What happens next

The maintainer will most likely "prompt" these specific problems away - feed the findings to an AI and ship a patch. But fixing 21 specific findings doesn't fix the process that created them. Without code review, without a PR process, without basic automated testing, without anyone who understands security fundamentals actually reviewing what ships - the next batch of features will introduce the next batch of vulnerabilities. This is only the start. The community needs to demand better coding standards, more controlled development, and a sensible roadmap.

## Full Security Review

See [Huntarr.io_SECURITY_REVIEW.md](Huntarr.io_SECURITY_REVIEW.md) for the complete security audit covering auth architecture, session management, API surface, and supply chain -21 findings total across critical, high, and medium severity.
