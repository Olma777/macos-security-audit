# macOS Security Audit Tool

A single-file terminal utility that runs a comprehensive security audit on macOS and generates a detailed HTML report with a security score and one-click fix commands.

![macOS](https://img.shields.io/badge/macOS-12%2B-000000?logo=apple&logoColor=white)
![Arch](https://img.shields.io/badge/Intel%20%26%20Apple%20Silicon-universal-8A2BE2)
![License](https://img.shields.io/badge/license-MIT-green)
![Shell](https://img.shields.io/badge/bash-no%20dependencies-blue)

---

## What It Does

One script. One command. ~55 security checks in 30 seconds.

The tool audits your Mac's security configuration and produces:

- **Security Score (0–100)** — weighted rating based on check severity
- **PASS / FAIL / WARN** — clear status for every check
- **Quick Fix block** — all fix commands collected in one place, click to copy
- **HTML report** — dark theme, opens offline in any browser, saved to your Desktop

The script is **read-only** — it checks settings but changes nothing. All fix commands are provided as recommendations for you to run manually.

## What Gets Checked

| Category | Checks |
|---|---|
| **System Integrity** | SIP, FileVault, Gatekeeper, XProtect, Rapid Security Responses, auto-updates, EFI integrity (Intel) / Secure Boot (Apple Silicon) |
| **Network Security** | Application Firewall + Stealth Mode, VPN tunnel detection (any VPN), DNS leak check, default route analysis, outbound firewall (LuLu / Little Snitch), 7 sharing services, AirDrop, Bluetooth, Wi-Fi saved networks |
| **Privacy Controls** | Apple Analytics, Crash Reporter, personalized ads, Siri & Siri Data Sharing, Spotlight Suggestions, Safari Suggestions, Location Services, privacy browser detection, telemetry-heavy browser detection |
| **Access & Auth** | Screensaver/sleep password & delay, auto-login, password hints, login window config, display sleep timeout, SSH, sudo timeout, Find My Mac |
| **Application Security** | Launch Agents & Daemons audit (3 levels with trusted whitelist), Login Items, Gatekeeper bypass check, quarantine flags, security tool detection |
| **Performance & Health** | Memory pressure, swap, disk space, user caches, APFS snapshots, battery health & cycle count, optimized charging, uptime |
| **TCC Permissions** *(bonus, requires sudo)* | Camera, Microphone, Screen Recording, Full Disk Access, Accessibility, Input Monitoring — lists which apps have access |

## Requirements

- **macOS 12+** (Monterey, Ventura, Sonoma, Sequoia)
- **Intel or Apple Silicon** — architecture is auto-detected
- **No dependencies** — uses only built-in macOS utilities
- **sudo** — optional but recommended. Enables Firewall, TCC, and SSH checks. Without it, those checks are skipped gracefully

## Quick Start

```bash
# Download
curl -sL https://raw.githubusercontent.com/Olma777/macos-security-audit/main/macos_security_audit.sh -o macos_security_audit.sh

# Make executable
chmod +x macos_security_audit.sh

# Run
./macos_security_audit.sh
```

Or clone the repo:

```bash
git clone https://github.com/Olma777/macos-security-audit.git
cd macos-security-audit
chmod +x macos_security_audit.sh
./macos_security_audit.sh
```

The script will ask for your password once (for sudo checks), run all audits with color-coded terminal output, generate an HTML report on your Desktop, and open it in your browser automatically.

## HTML Report

The report is a single self-contained HTML file — no external dependencies, works offline.

- Dark theme with high contrast, minimal typography
- Visual score ring with weighted security rating
- Every check with status, description, and fix command
- Click-to-copy on all fix commands
- Quick Fix section — all FAIL commands in one copyable block
- Manual recommendations for things the script can't automate (browser hardening, password manager, MFA strategy, backup)

## VPN & Security Tool Awareness

The script auto-detects your security setup and adapts accordingly:

**VPN Detection** — Auto-detects any active VPN tunnel (utun interface) and identifies the VPN client: Mullvad, NordVPN, ExpressVPN, ProtonVPN, WireGuard, OpenVPN, Surfshark, Cloudflare WARP, and others. If no VPN is found, recommends no-log VPN providers.

**DNS Leak Check** — Compares active DNS servers against known VPN DNS ranges and privacy-friendly public DNS (Cloudflare 1.1.1.1, Quad9 9.9.9.9, OpenDNS). Flags ISP DNS as a potential leak.

**Outbound Firewall** — Detects LuLu and Little Snitch. If neither is found, recommends installing one (macOS has no built-in outbound firewall).

**Privacy Browsers** — Detects DuckDuckGo, Firefox, Brave, LibreWolf, Tor Browser as positive signals. Flags Chrome, Edge, Opera, Yandex as high-telemetry browsers.

**Security Tools** — Detects Objective-See tools (LuLu, BlockBlock, KnockKnock, OverSight, RansomWhere?) and reports their presence.

**Trusted Whitelist** — VPN processes, security tools, and Apple services are whitelisted in Launch Agent/Daemon audits to avoid false positives.

## Safety

- **Read-only** — the script only reads system settings, it never modifies anything
- All fix commands are suggestions — you decide what to apply
- Destructive actions (like clearing caches) are clearly marked with warnings
- The sudo session is automatically cleaned up when the audit finishes
- Generated reports contain system-specific data — `.gitignore` excludes them by default

## Portability

The script is designed to work across multiple Macs:

- Auto-detects Intel vs Apple Silicon and adjusts checks accordingly
- No hardcoded paths or usernames
- No external dependencies (no Homebrew, no Python, no npm)
- One file — copy to any Mac, run, get results

## Roadmap

- [ ] Scheduled runs via launchd
- [ ] Report diffing between runs
- [ ] JSON export for automation
- [ ] Hardening profiles (basic / strict / paranoid)
- [ ] Homebrew formula

## License

[MIT](LICENSE) — free to use, modify, and distribute.

---

Built with a defense-in-depth approach, aligned with [CIS Benchmark for macOS](https://www.cisecurity.org/benchmark/apple_os). Each layer compensates for potential weaknesses in others.
