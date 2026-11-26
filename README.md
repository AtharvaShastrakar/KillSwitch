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
