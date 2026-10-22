# Scrubber

Scrubber removes sensitive values from pasted configs. It replaces each value with `*REDACTED*`.
The service runs in Docker on your machine. It does not send text anywhere and does not log it.

## Start

Put the `scrubber` folder somewhere permanent, for example `C:\Tools\scrubber`. Then double-click a file:

| File | What it does |
|---|---|
| `Setup.cmd` | First time only. Installs WSL and Docker Desktop if they are missing, adds `127.0.0.2 scrubber.test` to the hosts file, then starts the Scrubber. Asks for administrator rights. |
| `Start.cmd` | Starts Docker Desktop and the Scrubber, then opens http://scrubber.test. Also use it after you copy in a new version. |
| `Restart.cmd` | Restarts the Scrubber. |
| `Stop.cmd` | Stops the Scrubber. |

If Setup tells you to restart Windows, restart and run `Setup.cmd` again. A new PC can need this twice, once for WSL and once for Docker Desktop.
The first time Docker Desktop starts, it shows its terms. Accept them, and Setup continues.

The container starts again by itself after a reboot, but only when Docker Desktop runs. To start Docker Desktop at sign-in, open Docker Desktop, go to **Settings → General** and select **Start Docker Desktop when you sign in**.

More actions (run in PowerShell in this folder):
```
powershell -ExecutionPolicy Bypass -File .\scripts\scrubber.ps1 -Action Status
powershell -ExecutionPolicy Bypass -File .\scripts\scrubber.ps1 -Action Logs
```

## Use

1. Paste a config into the **Input** pane.
2. Click **Scrub** or press Ctrl+Enter.
3. Click **Copy result**.

Turn on **Scrub on paste** to skip step 2.
Open **Findings** to see what the scrubber removed. Select **Show original values** to see the values.

## What the scrubber removes

| Category | Examples |
|---|---|
| IP addresses | `10.20.30.40`, `fe80::1`, CIDR ranges |
| DNS names / hosts / servers | `sql01.corp.local`, `Server=SQLPROD01`, `"Host": "..."` |
| Non-standard URLs | Any URL whose host is not in the allowlist |
| Database names | `Initial Catalog=...`, `Database=...`, `"DbName": "..."` |
| API keys, tokens, secrets | `ApiKey`, `AccountKey`, JWTs, GitHub/AWS/Slack/Stripe keys, private key blocks |
| Client IDs | `ClientId`, `AppId`, `Audience` |
| Client secrets | `ClientSecret`, Azure AD secret format (`xxx8Q~...`) |
| Tenant IDs | `TenantId`, `Tenant` |
| Passwords and user names | `Password=`, `User ID=`, `user:pass@` in URLs |
| Other GUIDs | All GUIDs not covered above |
| Other high-entropy strings | Long random strings (32+ characters) |
| Custom terms | Your own list |

The scrubber reads JSON, XML (`web.config`, `<add key=... value=...>`), YAML, `.env`, INI and connection strings.
It finds values in two ways:

* **By key name.** It redacts the value of keys like `ClientSecret`, `TenantId` or `Server`.
* **By value shape.** It redacts IPs, GUIDs, hostnames, URLs and known key formats anywhere in the text.

The scrubber keeps assembly versions (`Version=5.2.7.0`), `PublicKeyToken`, .NET namespaces (`Microsoft.AspNetCore`), placeholders (`${VAR}`, `{{x}}`) and allowlisted hosts.

## Settings

Open **Settings** on the page to:

* Turn categories on or off.
* Edit the allowlist. Use `*.domain.se` to keep all subdomains.
* Add parameters. The scrubber redacts the value of each parameter and keeps the name. Example: `NoReplyEmailAddress` turns `"NoReplyEmailAddress": "a@b.se"` into `"NoReplyEmailAddress": "*REDACTED*"`.
* Add custom terms. The scrubber redacts this exact text anywhere, for example customer names.

Click **Save settings** (or press Ctrl+S) to save the lists. The page writes them to `config/sensitive_keys.txt`, `config/custom_terms.txt` and `config/allowlist.txt`. The saved lists stay after a restart or a rebuild. Click **Discard changes** to load the saved lists again.

You can also edit the three files directly. Reload the page after you edit them.

The browser stores only the category checkboxes and the **Scrub on paste** option.

## Security

* Docker publishes the port on the loopback IP `127.0.0.2` only. Other machines cannot connect.
* The container runs as a non-root user with a read-only file system and no capabilities. It can write only to the `config` folder.
* The service has no access log. It does not store input.
* The page loads no external scripts, fonts or styles. A strict Content Security Policy blocks them.

The scrubber uses rules, not AI. It can miss values or redact too much. Always read the result before you share it.

## Address and port

Each local app gets its own loopback IP, so each app can use port 80 and needs no port in the URL.

| App | Hosts file line | `ports:` in docker-compose.yml |
|---|---|---|
| Scrubber | `127.0.0.2   scrubber.test` | `127.0.0.2:80:8080` |
| Next app | `127.0.0.3   otherapp.test` | `127.0.0.3:80:<app port>` |

Use `.test` names. Browsers ignore the hosts file for `.localhost` names, and `.local` names can be slow.

To change the IP or the name, edit `$HostIp` and `$HostName` at the top of `scripts\scrubber.ps1`, then run `Setup.cmd`.

If http://scrubber.test does not open but `Start.cmd` reports that the Scrubber runs, a company proxy can be the cause. Add `*.test` to the proxy exceptions in **Windows Settings → Network & internet → Proxy**.

If Docker shows "port is already allocated" or "access forbidden", another program listens on port 80 on all addresses. This is usually IIS. Run `netstat -ano | findstr ":80 "` to find it.

To use a port instead, change the `ports:` line to `127.0.0.1:8710:8080` and open http://localhost:8710.

## Run tests

```
pip install fastapi==0.115.6 uvicorn==0.34.0 pytest httpx
python -m pytest
```
