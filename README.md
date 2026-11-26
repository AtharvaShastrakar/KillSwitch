# KillSwitch: auto-lock and remote wipe for unreturned laptops (prototype)

When an employee leaves and doesn't return their laptop:

```
Resigns ─▶ OFFBOARDING ─last day─▶ GRACE (10 days) ─not returned─▶ LOCKED ─still missing─▶ WIPE PENDING ─2 admins approve─▶ WIPED
                                        │                             │
                                        └──── returned ──────────────┴──▶ RETURNED (unlock with recovery key, re-image, reissue)
```

- **Lock** removes BitLocker's TPM key. The laptop then boots to the BitLocker recovery screen with your "return to IT" message. IT can undo this with the escrowed recovery key.
- **Wipe** destroys the escrowed recovery key (crypto-shred) and runs Windows' protected factory reset. This is permanent. It needs approval from **two different admins**.
- **Offline safety net:** if a laptop doesn't check in before its 7-day lease runs out, the agent locks it on its own.
- **Reinstall protection:** if a locked or wiped laptop's serial number enrolls again, it gets locked again.

> ⚠️ **The agent ships with `"dryRun": true`.** In dry-run mode it only *logs* what it would do. Test on a spare laptop before setting it to `false`.

## Project layout

```
server/            Node.js (Express) API, workflow engine and admin dashboard
  src/             config, database (SQLite), crypto, services, routes
  public/          admin dashboard (HTML/CSS/JS)
agent/             Go agent that runs on each laptop
  dist/            prebuilt binaries (Windows .exe + macOS/Linux for dry-run demos)
  install.ps1      Windows installer (runs the agent as SYSTEM at startup)
scripts/           send-hr-webhook.mjs simulates your HR system
docs/              architecture + workflow diagrams
```

## 1. Run the demo on your Mac (about 5 minutes)

Requirements: **Node.js 22.13 or newer** (`node -v`). The demo agent comes prebuilt.

```bash
cd server
npm install
npm run demo          # demo mode: 1 "day" = 10 seconds
```

The first start prints two admin logins (`admin1` and `admin2`, also saved in `server/data-demo/initial-admins.txt`). Open http://localhost:8080 and sign in as **admin1**.

1. **Employees** tab: add an employee, e.g. `E101 / Rahul Mehta`.
2. **Enroll laptops** tab: click **Create token** and copy the config JSON into `agent/config.json`. For a second fake laptop, add `"serialOverride": "TEST-002"`.
3. Start the agent in a second terminal:
   ```bash
   cd agent
   chmod +x dist/killswitch-agent-macos-arm64     # use ...-macos-intel on Intel Macs
   ./dist/killswitch-agent-macos-arm64 -config config.json
   ```
4. **Devices** tab: the laptop appears. Click **Assign** and pick Rahul.
5. **Employees** tab: click **Start offboarding**, with the last day 1 demo day away.
6. Watch the Devices tab. About 10 s later the employee has left and the laptop is in **GRACE**. About 100 s after that it is **LOCKED**. The agent terminal shows the signed lock command.
7. Click **Request wipe** (or wait for the wipe deadline), then **Approve wipe**. Sign out, sign in as **admin2** in a private window and approve again. The laptop is now **WIPED**.
8. Try **Mark returned** and **Recovery key** on another laptop, and look at the **Audit log** tab.

Simulating the HR system instead of clicking (the webhook URL and secret are on the Enroll laptops tab):
```bash
node scripts/send-hr-webhook.mjs http://localhost:8080 <secret> create E102 "Priya Nair" priya@co.com
node scripts/send-hr-webhook.mjs http://localhost:8080 <secret> exit E102 --in-days 1
```

## 2. Test on a real Windows laptop (spare or test machine only)

1. Turn on BitLocker on that laptop (`manage-bde -status C:` should show *Protection On*).
2. Run the server where the laptop can reach it. Set `PUBLIC_URL` to that address and use HTTPS outside a lab.
3. Copy `agent/dist/killswitch-agent.exe`, `agent/install.ps1` and a `config.json` from the dashboard into one folder on the laptop.
4. In an Administrator PowerShell window, run `powershell -ExecutionPolicy Bypass -File .\install.ps1`.
5. Check that the dashboard shows **key escrowed ✓** for the laptop. `install.ps1` deletes the copied `config.json` afterwards, because it contains the enrollment token.
6. With `dryRun: true`, run through the whole flow. Then set `dryRun: false` in `C:\Program Files\KillSwitch\config.json` and restart the `KillSwitchAgent` scheduled task. Within one check-in, the agent replaces the dry-run (fake) key with the laptop's real recovery key. Wait until the dashboard shows **key escrowed ✓** (not **⚠ key out of sync**), then test **Lock now**:
   - The laptop reboots to the BitLocker recovery screen.
   - Unlock it with **Recovery key** from the dashboard and click **Mark returned**.
   - The agent restores the TPM key and rotates the recovery key.
7. Test the wipe last, on a machine you can afford to lose.

To remove the agent, run `uninstall.ps1` as Administrator.

**Re-installing an already enrolled laptop** (for example after a Windows reinstall): click **Allow re-enroll** on that laptop in the dashboard first. Re-enrollment stays open for 24 hours. Without it, the server refuses the enrollment and logs `ALERT_REENROLL_BLOCKED`, so nobody can take over another laptop's record with an enrollment token.

**Employee is staying after all:** on the **Employees** tab, click **Cancel exit** (or send the HR webhook event `employee.exit_cancelled`). Their laptops go back to normal. A laptop that was already locked is restored automatically once IT enters its recovery key.

## 3. Production settings

Copy `server/.env.example` to `server/.env`, edit it, and run `node --env-file=.env src/index.js`.

| Setting | Default | Meaning |
|---|---|---|
| `GRACE_DAYS` | 10 | Days after the last working day before the laptop locks |
| `WIPE_AFTER_LOCK_DAYS` | 20 | Days after locking before a wipe needs approval |
| `LEASE_DAYS` | 7 | Days offline before the agent locks the laptop by itself |
| `REQUIRED_WIPE_APPROVALS` | 2 | Number of different admins needed to approve a wipe |
| `WIPE_MAX_PER_HOUR` | 3 | Mass-wipe protection; extra wipes are held and raise an alert |
| `LOCK_MESSAGE` | … | Text shown on the BitLocker recovery screen |
| `TZ_OFFSET` | +05:30 | Timezone of "last working day" dates (the day ends at 23:59:59 in this offset) |

Run the tests with `npm test` (server) and `go test ./...` (agent).

## Security design

- Commands and leases are **signed with Ed25519**. The agent pins the server's public key from `config.json` and rejects anything else, including expired commands and replays.
- Each laptop gets its own random token. Enrollment tokens are limited in uses and time.
- Recovery keys are stored **encrypted with AES-256-GCM**. Revealing one is written to the audit log.
- The **audit log is append-only**; database triggers block edits and deletes.
- Admin logins are throttled, sessions use HttpOnly/SameSite cookies, and the dashboard runs under a strict Content Security Policy.
- The agent detects the system clock being moved backwards (an attempt to dodge the lease) and locks the laptop.
