#!/bin/bash
set -uo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  macOS Security Audit Tool v1.1                                             ║
# ║  Comprehensive macOS security audit with HTML report                        ║
# ║  Compatibility: macOS 12+ (Monterey), Intel & Apple Silicon                 ║
# ║  VPN-aware | Outbound Firewall-aware | Privacy Browser-aware                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

SCRIPT_VERSION="1.1.0"
AUDIT_DATE=$(date "+%Y-%m-%d %H:%M:%S")
AUDIT_TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
HOSTNAME_VAL=$(hostname)
MACOS_VERSION=$(sw_vers -productVersion)
MACOS_BUILD=$(sw_vers -buildVersion)
MACOS_NAME=$(sw_vers -productName 2>/dev/null || echo "macOS")
HARDWARE_MODEL=$(sysctl -n hw.model 2>/dev/null || echo "Unknown")
ARCH=$(uname -m)
SERIAL=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $NF}' || echo "N/A")
CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")

REPORT_DIR="${HOME}/Desktop"
REPORT_FILE="${REPORT_DIR}/security_audit_${AUDIT_TIMESTAMP}.html"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TOTAL_CHECKS=0; PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; SKIP_COUNT=0
declare -a RESULTS_JSON=()
declare -a QUICK_FIXES=()

# ── Whitelist: Apple + популярные VPN + security tools ──
TRUSTED_PATTERNS=(
    "com.apple." "com.mullvad" "com.nordvpn" "com.expressvpn"
    "ch.protonvpn" "com.protonvpn" "com.wireguard" "com.openvpn"
    "com.surfshark" "com.privateinternetaccess" "com.cloudflare.warp"
    "com.cisco.anyconnect" "com.objective-see.lulu" "com.objective-see"
    "com.duckduckgo" "com.littlesnitch" "at.obdev.littlesnitch"
)

# ── VPN-процессы для автоопределения ──
VPN_PROCESS_PATTERNS=(
    "mullvad:Mullvad VPN" "nordvpn:NordVPN" "expressvpn:ExpressVPN"
    "protonvpn:ProtonVPN" "wireguard:WireGuard" "openvpn:OpenVPN"
    "surfshark:Surfshark" "cloudflare-warp:Cloudflare WARP"
)

# ── VPN DNS-диапазоны ──
VPN_DNS_PATTERNS=("10.64.0" "100.64.0" "10.124.0" "10.2.0.1" "103.86.96" "103.86.99")

# ── Privacy-friendly public DNS ──
SAFE_PUBLIC_DNS=("1.1.1.1" "1.0.0.1" "9.9.9.9" "149.112.112.112" "208.67.222.222" "208.67.220.220")

# ══════════════════════════════════════════════════════════════════════════════
print_banner() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║       macOS Security Audit Tool v${SCRIPT_VERSION}                  ║${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  ${NC}${DIM}Host:${NC}  ${HOSTNAME_VAL}"
    echo -e "${CYAN}║  ${NC}${DIM}macOS:${NC} ${MACOS_VERSION} (${MACOS_BUILD})"
    echo -e "${CYAN}║  ${NC}${DIM}Chip:${NC}  ${CHIP}"
    echo -e "${CYAN}║  ${NC}${DIM}Arch:${NC}  ${ARCH}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  ${1}. ${2}${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

record_check() {
    local category="$1" name="$2" status="$3" detail="$4" fix="${5:-}" weight="${6:-1}" priority="${7:-recommended}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}✓ PASS${NC}  ${name}" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "  ${RED}✗ FAIL${NC}  ${name}"
              [[ -n "$fix" ]] && echo -e "         ${DIM}Fix: ${fix}${NC}" ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)); echo -e "  ${YELLOW}⚠ WARN${NC}  ${name}" ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)); echo -e "  ${DIM}○ SKIP${NC}  ${name} ${DIM}(${detail})${NC}" ;;
    esac
    local sd se sn
    sd=$(echo "$detail" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g; s/&/\&amp;/g')
    se=$(echo "$fix" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g; s/&/\&amp;/g')
    sn=$(echo "$name" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g')
    RESULTS_JSON+=("{\"category\":\"${category}\",\"name\":\"${sn}\",\"status\":\"${status}\",\"detail\":\"${sd}\",\"fix\":\"${se}\",\"weight\":${weight},\"priority\":\"${priority}\"}")
    [[ "$status" == "FAIL" && -n "$fix" ]] && QUICK_FIXES+=("# ${name}|${fix}")
}

is_trusted() {
    local item="$1"
    for p in "${TRUSTED_PATTERNS[@]}"; do [[ "$item" == *"$p"* ]] && return 0; done
    return 1
}

detect_vpn() {
    local detected=""
    for vp in "${VPN_PROCESS_PATTERNS[@]}"; do
        local proc="${vp%%:*}" vname="${vp##*:}"
        if pgrep -fi "$proc" >/dev/null 2>&1; then
            detected="${detected:+${detected}, }${vname}"
        fi
    done
    echo "$detected"
}

is_safe_dns() {
    local dns="$1"
    [[ "$dns" == "127."* || "$dns" == "::1" || "$dns" == "fe80:"* ]] && return 0
    for p in "${VPN_DNS_PATTERNS[@]}"; do [[ "$dns" == ${p}* ]] && return 0; done
    for s in "${SAFE_PUBLIC_DNS[@]}"; do [[ "$dns" == "$s" ]] && return 0; done
    return 1
}

request_sudo() {
    echo -e "${YELLOW}Some checks require sudo (Firewall, TCC, system settings).${NC}"
    echo -e "${DIM}Password is requested once and cached for the audit duration.${NC}"
    echo ""
    sudo -v 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo -e "${YELLOW}⚠ sudo unavailable. Some checks will be skipped.${NC}"
        HAS_SUDO=false
    else
        HAS_SUDO=true
        while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
        SUDO_KEEPER_PID=$!
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. SYSTEM INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
check_system_integrity() {
    print_section "1" "SYSTEM INTEGRITY"

    local sip_status; sip_status=$(csrutil status 2>/dev/null || echo "Unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        record_check "System Integrity" "SIP (System Integrity Protection)" "PASS" "SIP is enabled" "" 5 "critical"
    else
        record_check "System Integrity" "SIP (System Integrity Protection)" "FAIL" "SIP is disabled — system vulnerable to rootkits and system file modification" "Reboot to Recovery Mode → Terminal → csrutil enable" 5 "critical"
    fi

    local fv_status; fv_status=$(fdesetup status 2>/dev/null || echo "Unknown")
    if echo "$fv_status" | grep -q "FileVault is On"; then
        record_check "System Integrity" "FileVault 2 (Disk Encryption)" "PASS" "FileVault is enabled" "" 5 "critical"
    elif echo "$fv_status" | grep -q "Encryption in progress"; then
        record_check "System Integrity" "FileVault 2 (Disk Encryption)" "WARN" "FileVault: encryption in progress" "" 5 "critical"
    else
        record_check "System Integrity" "FileVault 2 (Disk Encryption)" "FAIL" "Disk is not encrypted — data accessible with physical access" "sudo fdesetup enable" 5 "critical"
    fi

    local gk_status; gk_status=$(spctl --status 2>/dev/null || echo "Unknown")
    if echo "$gk_status" | grep -q "assessments enabled"; then
        record_check "System Integrity" "Gatekeeper" "PASS" "Gatekeeper is active" "" 4 "critical"
    else
        record_check "System Integrity" "Gatekeeper" "FAIL" "Gatekeeper is disabled — unsigned apps can run" "sudo spctl --master-enable" 4 "critical"
    fi

    local auto_update; auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" == "1" ]]; then
        record_check "System Integrity" "Automatic macOS Updates" "PASS" "Automatic macOS updates enabled" "" 3 "important"
    else
        record_check "System Integrity" "Automatic macOS Updates" "FAIL" "Automatic macOS updates disabled" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true" 3 "important"
    fi

    local critical_update; critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$critical_update" == "1" ]]; then
        record_check "System Integrity" "Rapid Security Responses" "PASS" "Rapid Security Responses enabled" "" 4 "critical"
    else
        record_check "System Integrity" "Rapid Security Responses" "FAIL" "Rapid Security Responses disabled — critical patches not auto-installed" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true" 4 "critical"
    fi

    local auto_check; auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "not set")
    if [[ "$auto_check" == "1" ]]; then
        record_check "System Integrity" "Automatic Update Check" "PASS" "Automatic update check enabled" "" 2 "important"
    else
        record_check "System Integrity" "Automatic Update Check" "FAIL" "Automatic update check disabled" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true" 2 "important"
    fi

    local auto_download; auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "not set")
    if [[ "$auto_download" == "1" ]]; then
        record_check "System Integrity" "Automatic Update Download" "PASS" "Automatic download enabled" "" 2 "important"
    else
        record_check "System Integrity" "Automatic Update Download" "FAIL" "Automatic download disabled" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true" 2 "important"
    fi

    local app_update; app_update=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "not set")
    if [[ "$app_update" == "1" ]]; then
        record_check "System Integrity" "App Store Auto-Update" "PASS" "App Store auto-update enabled" "" 1 "recommended"
    else
        record_check "System Integrity" "App Store Auto-Update" "WARN" "App Store auto-update not enabled" "sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true" 1 "recommended"
    fi

    if [[ "$ARCH" == "x86_64" ]]; then
        if [[ -f "/usr/libexec/firmwarecheckers/eficheck/eficheck" ]]; then
            local efi_result; efi_result=$(/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check 2>&1 || true)
            if echo "$efi_result" | grep -qi "passed\|No changes"; then
                record_check "System Integrity" "EFI Firmware Integrity" "PASS" "EFI firmware integrity check passed" "" 5 "critical"
            elif echo "$efi_result" | grep -qi "not supported\|error"; then
                record_check "System Integrity" "EFI Firmware Integrity" "SKIP" "EFI check not supported on this Mac" "" 0 "info"
            else
                record_check "System Integrity" "EFI Firmware Integrity" "WARN" "EFI firmware: ambiguous result — manual check recommended" "" 5 "critical"
            fi
        fi
    else
        record_check "System Integrity" "Secure Boot (Apple Silicon)" "PASS" "Apple Silicon uses Secure Boot by default (Full Security)" "" 5 "critical"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. NETWORK SECURITY
# ══════════════════════════════════════════════════════════════════════════════
check_network_security() {
    print_section "2" "NETWORK SECURITY"

    local fw_state=""
    [[ "$HAS_SUDO" == true ]] && fw_state=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "")
    if echo "$fw_state" | grep -q "enabled"; then
        record_check "Network Security" "Application Firewall" "PASS" "Firewall is enabled" "" 4 "critical"
    elif [[ -z "$fw_state" ]]; then
        record_check "Network Security" "Application Firewall" "SKIP" "Requires sudo" "" 4 "critical"
    else
        record_check "Network Security" "Application Firewall" "FAIL" "Firewall is disabled — incoming connections are not filtered" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" 4 "critical"
    fi

    local stealth=""
    [[ "$HAS_SUDO" == true ]] && stealth=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "")
    if echo "$stealth" | grep -q "enabled"; then
        record_check "Network Security" "Firewall Stealth Mode" "PASS" "Stealth Mode enabled — invisible to network scanners" "" 3 "important"
    elif [[ -z "$stealth" ]]; then
        record_check "Network Security" "Firewall Stealth Mode" "SKIP" "Requires sudo" "" 3 "important"
    else
        record_check "Network Security" "Firewall Stealth Mode" "FAIL" "Stealth Mode disabled — Mac responds to ping/port scan" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on" 3 "important"
    fi

    local block_all=""
    [[ "$HAS_SUDO" == true ]] && block_all=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo "")
    if echo "$block_all" | grep -q "enabled"; then
        record_check "Network Security" "Block All Incoming" "PASS" "All incoming connections blocked" "" 2 "important"
    elif [[ -z "$block_all" ]]; then
        record_check "Network Security" "Block All Incoming" "SKIP" "Requires sudo" "" 2 "important"
    else
        record_check "Network Security" "Block All Incoming" "WARN" "Block All Incoming disabled — service exceptions allowed" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on" 2 "important"
    fi

    # ── VPN Tunnel ──
    local vpn_tunnel; vpn_tunnel=$(ifconfig 2>/dev/null | grep -c "utun" || echo "0")
    local detected_vpn; detected_vpn=$(detect_vpn)

    if [[ "$vpn_tunnel" -gt 0 && -n "$detected_vpn" ]]; then
        record_check "Network Security" "VPN Tunnel" "PASS" "VPN tunnel active (${detected_vpn})" "" 5 "critical"
    elif [[ "$vpn_tunnel" -gt 0 ]]; then
        record_check "Network Security" "VPN Tunnel" "PASS" "VPN tunnel active (utun interface detected)" "" 5 "critical"
    else
        record_check "Network Security" "VPN Tunnel" "WARN" "No VPN tunnel detected — traffic goes through ISP unencrypted. A no-log VPN is strongly recommended (Mullvad, ProtonVPN, IVPN)." "Recommendation: https://mullvad.net or https://protonvpn.com" 5 "critical"
    fi

    # ── DNS Security ──
    local dns_servers; dns_servers=$(scutil --dns 2>/dev/null | grep "nameserver\[" | awk '{print $3}' | sort -u)
    local unsafe_dns=(); local vpn_dns_found=false; local has_dns=false

    if [[ -n "$dns_servers" ]]; then
        while IFS= read -r dns; do
            [[ -z "$dns" ]] && continue
            has_dns=true
            if is_safe_dns "$dns"; then
                for p in "${VPN_DNS_PATTERNS[@]}"; do [[ "$dns" == ${p}* ]] && vpn_dns_found=true && break; done
            else
                unsafe_dns+=("$dns")
            fi
        done <<< "$dns_servers"
    fi

    if [[ "$has_dns" == false ]]; then
        record_check "Network Security" "DNS Security" "WARN" "Could not determine DNS servers" "" 5 "critical"
    elif [[ ${#unsafe_dns[@]} -eq 0 && "$vpn_dns_found" == true ]]; then
        record_check "Network Security" "DNS Security" "PASS" "DNS queries go through VPN — no leaks detected" "" 5 "critical"
    elif [[ ${#unsafe_dns[@]} -eq 0 ]]; then
        record_check "Network Security" "DNS Security" "PASS" "DNS servers are safe (privacy-friendly or VPN)" "" 5 "critical"
    else
        local ul; ul=$(printf ", %s" "${unsafe_dns[@]}"); ul="${ul:2}"
        if [[ "$vpn_tunnel" -gt 0 ]]; then
            record_check "Network Security" "DNS Security" "WARN" "VPN active but non-VPN DNS detected: ${ul} — possible DNS leak. Configure DNS in VPN client." "Check DNS settings in your VPN client" 5 "critical"
        else
            record_check "Network Security" "DNS Security" "WARN" "ISP or unknown DNS: ${ul} — ISP can see all DNS queries. Use VPN or privacy DNS (1.1.1.1, 9.9.9.9)." "networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1" 4 "important"
        fi
    fi

    # ── Default Route ──
    local default_route; default_route=$(route -n get default 2>/dev/null | grep "interface:" | awk '{print $2}' || echo "")
    if [[ "$default_route" == utun* ]]; then
        record_check "Network Security" "Default Route via VPN" "PASS" "Default route goes through VPN tunnel (${default_route})" "" 4 "critical"
    elif [[ "$vpn_tunnel" -gt 0 && -n "$default_route" ]]; then
        record_check "Network Security" "Default Route via VPN" "WARN" "Default route: ${default_route} — not through VPN. VPN may use split tunneling." "" 3 "important"
    elif [[ -n "$default_route" ]]; then
        record_check "Network Security" "Default Route" "WARN" "Route: ${default_route} — without VPN all traffic is visible to ISP" "" 3 "important"
    fi

    # ── Outbound Firewall ──
    local obfw_found=false obfw_name="" obfw_running=false
    if [[ -d "/Applications/LuLu.app" ]]; then
        obfw_found=true; obfw_name="LuLu"
        pgrep -x "LuLu" >/dev/null 2>&1 && obfw_running=true
    fi
    if [[ -d "/Applications/Little Snitch.app" || -d "/Library/Little Snitch" ]]; then
        obfw_found=true; obfw_name="${obfw_name:+${obfw_name} + }Little Snitch"
        pgrep -f "Little Snitch" >/dev/null 2>&1 && obfw_running=true
    fi

    if [[ "$obfw_found" == true && "$obfw_running" == true ]]; then
        record_check "Network Security" "Outbound Firewall" "PASS" "${obfw_name} installed and running — outbound connections monitored" "" 3 "important"
    elif [[ "$obfw_found" == true ]]; then
        record_check "Network Security" "Outbound Firewall" "WARN" "${obfw_name} installed but not running" "Launch ${obfw_name} from /Applications" 3 "important"
    else
        record_check "Network Security" "Outbound Firewall" "WARN" "No outbound firewall detected. macOS has no built-in outbound filtering. Recommended: LuLu (free, open-source) or Little Snitch." "LuLu: https://objective-see.org/products/lulu.html" 3 "important"
    fi

    # ── Sharing Services ──
    local sharing_services=("Remote Login:ssh" "Screen Sharing:screensharing" "File Sharing:smb" "Remote Management:remotemanagement" "Printer Sharing:printersharing" "Content Caching:contentcaching" "Remote Apple Events:remoteappleevents")
    for sp in "${sharing_services[@]}"; do
        local dn="${sp%%:*}" sn="${sp##*:}" is_on=false
        case "$sn" in
            ssh) local ss; ss=$(sudo systemsetup -getremotelogin 2>/dev/null || echo ""); echo "$ss" | grep -qi "on" && is_on=true ;;
            *) launchctl list 2>/dev/null | grep -qi "$sn" && is_on=true ;;
        esac
        if [[ "$is_on" == true ]]; then
            local fc=""; [[ "$sn" == "ssh" ]] && fc="sudo systemsetup -setremotelogin off" || fc="System Settings → General → Sharing → disable ${dn}"
            record_check "Network Security" "Sharing: ${dn}" "FAIL" "${dn} is enabled — potential entry point" "$fc" 3 "important"
        else
            record_check "Network Security" "Sharing: ${dn}" "PASS" "${dn} is disabled" "" 3 "important"
        fi
    done

    local airdrop; airdrop=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null || echo "not set")
    if [[ "$airdrop" == "Off" ]]; then
        record_check "Network Security" "AirDrop" "PASS" "AirDrop is off" "" 2 "recommended"
    elif [[ "$airdrop" == "Contacts Only" ]]; then
        record_check "Network Security" "AirDrop" "PASS" "AirDrop: Contacts Only" "" 2 "recommended"
    else
        record_check "Network Security" "AirDrop" "WARN" "AirDrop discoverable by everyone — set to Contacts Only or Off" "defaults write com.apple.sharingd DiscoverableMode -string 'Contacts Only'" 2 "recommended"
    fi

    local bt; bt=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "1")
    if [[ "$bt" == "0" ]]; then
        record_check "Network Security" "Bluetooth" "PASS" "Bluetooth is off — minimal attack surface" "" 1 "recommended"
    else
        record_check "Network Security" "Bluetooth" "WARN" "Bluetooth is on — increases attack surface. Turn off when not in use." "" 1 "recommended"
    fi

    local kn; kn=$(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2 | sed 's/^[[:space:]]*//' || echo "")
    local nc; nc=$(echo "$kn" | grep -c "." 2>/dev/null || echo "0")
    if [[ "$nc" -gt 10 ]]; then
        record_check "Network Security" "Wi-Fi: Saved Networks" "WARN" "${nc} saved Wi-Fi networks — remove unused ones (evil twin risk)" "networksetup -removepreferredwirelessnetwork en0 'NETWORK_NAME'" 2 "recommended"
    else
        record_check "Network Security" "Wi-Fi: Saved Networks" "PASS" "${nc} saved Wi-Fi networks" "" 2 "recommended"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. PRIVACY CONTROLS
# ══════════════════════════════════════════════════════════════════════════════
check_privacy_controls() {
    print_section "3" "PRIVACY CONTROLS"

    local an; an=$(defaults read /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null || echo "not set")
    [[ "$an" == "0" ]] && record_check "Privacy Controls" "Apple Analytics" "PASS" "Diagnostics sharing disabled" "" 2 "important" \
        || record_check "Privacy Controls" "Apple Analytics" "FAIL" "Diagnostics sharing enabled — Apple receives usage data" "sudo defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool false" 2 "important"

    local cr; cr=$(defaults read com.apple.CrashReporter DialogType 2>/dev/null || echo "not set")
    [[ "$cr" == "none" ]] && record_check "Privacy Controls" "Crash Reporter" "PASS" "Crash Reporter silent" "" 1 "recommended" \
        || record_check "Privacy Controls" "Crash Reporter" "WARN" "Crash Reporter may send data" "defaults write com.apple.CrashReporter DialogType -string 'none'" 1 "recommended"

    local ad; ad=$(defaults read com.apple.AdLib forceLimitAdTracking 2>/dev/null || echo "not set")
    [[ "$ad" == "1" ]] && record_check "Privacy Controls" "Personalized Ads" "PASS" "Personalized ads limited" "" 2 "important" \
        || record_check "Privacy Controls" "Personalized Ads" "FAIL" "Personalized ads not limited" "defaults write com.apple.AdLib forceLimitAdTracking -bool true" 2 "important"

    local si; si=$(defaults read com.apple.assistant.support "Assistant Enabled" 2>/dev/null || echo "not set")
    [[ "$si" == "0" ]] && record_check "Privacy Controls" "Siri" "PASS" "Siri is disabled" "" 2 "important" \
        || record_check "Privacy Controls" "Siri" "WARN" "Siri is enabled — voice queries may be processed on Apple servers" "defaults write com.apple.assistant.support 'Assistant Enabled' -bool false" 2 "important"

    local ss; ss=$(defaults read com.apple.assistant.support "Siri Data Sharing Opt-In Status" 2>/dev/null || echo "not set")
    if [[ "$ss" == "2" || "$ss" == "0" ]]; then
        record_check "Privacy Controls" "Siri Data Sharing" "PASS" "Siri data sharing disabled" "" 2 "important"
    elif [[ "$ss" == "not set" ]]; then
        record_check "Privacy Controls" "Siri Data Sharing" "WARN" "Siri data sharing status unknown" "" 2 "important"
    else
        record_check "Privacy Controls" "Siri Data Sharing" "FAIL" "Siri data sharing enabled" "defaults write com.apple.assistant.support 'Siri Data Sharing Opt-In Status' -int 2" 2 "important"
    fi

    local sl; sl=$(defaults read com.apple.lookup.shared LookupSuggestionsDisabled 2>/dev/null || echo "not set")
    [[ "$sl" == "1" ]] && record_check "Privacy Controls" "Spotlight Suggestions" "PASS" "Network Spotlight Suggestions disabled" "" 2 "important" \
        || record_check "Privacy Controls" "Spotlight Suggestions" "FAIL" "Spotlight Suggestions send search queries to Apple" "defaults write com.apple.lookup.shared LookupSuggestionsDisabled -bool true" 2 "important"

    local sf; sf=$(defaults read com.apple.Safari UniversalSearchEnabled 2>/dev/null || echo "not set")
    [[ "$sf" == "0" ]] && record_check "Privacy Controls" "Safari Suggestions" "PASS" "Safari Suggestions disabled" "" 1 "recommended" \
        || record_check "Privacy Controls" "Safari Suggestions" "WARN" "Safari Suggestions send queries to Apple" "defaults write com.apple.Safari UniversalSearchEnabled -bool false" 1 "recommended"

    local loc
    [[ "$HAS_SUDO" == true ]] && loc=$(sudo defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null || echo "not set") || loc="not set"
    if [[ "$loc" == "0" ]]; then record_check "Privacy Controls" "Location Services" "PASS" "Location Services disabled" "" 2 "important"
    elif [[ "$loc" == "1" ]]; then record_check "Privacy Controls" "Location Services" "WARN" "Location Services enabled — audit app access list" "System Settings → Privacy & Security → Location Services" 2 "important"
    else record_check "Privacy Controls" "Location Services" "SKIP" "Could not check (requires sudo)" "" 2 "important"; fi

    # Privacy browsers
    local pb=()
    [[ -d "/Applications/DuckDuckGo.app" ]] && pb+=("DuckDuckGo")
    [[ -d "/Applications/Firefox.app" ]] && pb+=("Firefox")
    [[ -d "/Applications/Brave Browser.app" ]] && pb+=("Brave")
    [[ -d "/Applications/LibreWolf.app" ]] && pb+=("LibreWolf")
    [[ -d "/Applications/Tor Browser.app" ]] && pb+=("Tor Browser")
    if [[ ${#pb[@]} -gt 0 ]]; then
        local bl; bl=$(printf ", %s" "${pb[@]}"); bl="${bl:2}"
        record_check "Privacy Controls" "Privacy Browser" "PASS" "Privacy-oriented browsers: ${bl}" "" 2 "recommended"
    else
        record_check "Privacy Controls" "Privacy Browser" "WARN" "No privacy browser found. Recommended: DuckDuckGo, Firefox (with arkenfox), Brave, LibreWolf" "https://duckduckgo.com/mac | https://mozilla.org/firefox" 2 "recommended"
    fi

    local rb=()
    [[ -d "/Applications/Google Chrome.app" ]] && rb+=("Google Chrome")
    [[ -d "/Applications/Microsoft Edge.app" ]] && rb+=("Microsoft Edge")
    [[ -d "/Applications/Opera.app" ]] && rb+=("Opera")
    [[ -d "/Applications/Yandex Browser.app" || -d "/Applications/Yandex.app" ]] && rb+=("Yandex Browser")
    if [[ ${#rb[@]} -gt 0 ]]; then
        local bl; bl=$(printf ", %s" "${rb[@]}"); bl="${bl:2}"
        record_check "Privacy Controls" "High-Telemetry Browsers" "WARN" "Browsers with elevated telemetry: ${bl}. Avoid for sensitive operations." "" 1 "recommended"
    else
        record_check "Privacy Controls" "High-Telemetry Browsers" "PASS" "No high-telemetry browsers detected" "" 1 "recommended"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. ACCESS & AUTH
# ══════════════════════════════════════════════════════════════════════════════
check_access_auth() {
    print_section "4" "ACCESS & AUTHENTICATION"

    local ap; ap=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "not set")
    [[ "$ap" == "1" ]] && record_check "Access & Auth" "Password on Wake" "PASS" "Password required after screensaver/sleep" "" 4 "critical" \
        || record_check "Access & Auth" "Password on Wake" "FAIL" "No password on wake — physical access = full access" "defaults write com.apple.screensaver askForPassword -int 1" 4 "critical"

    local ad; ad=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo "not set")
    if [[ "$ad" == "0" ]]; then record_check "Access & Auth" "Password Delay" "PASS" "Password required immediately (0s delay)" "" 3 "important"
    elif [[ "$ad" == "not set" ]]; then record_check "Access & Auth" "Password Delay" "WARN" "Password delay not configured" "defaults write com.apple.screensaver askForPasswordDelay -int 0" 3 "important"
    else record_check "Access & Auth" "Password Delay" "FAIL" "Delay: ${ad}s — window for unauthorized access" "defaults write com.apple.screensaver askForPasswordDelay -int 0" 3 "important"; fi

    local al; al=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "not set")
    [[ "$al" == "not set" ]] && record_check "Access & Auth" "Auto-Login" "PASS" "Auto-login disabled" "" 4 "critical" \
        || record_check "Access & Auth" "Auto-Login" "FAIL" "Auto-login enabled for: ${al}" "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser" 4 "critical"

    local sh; sh=$(defaults read com.apple.loginwindow RetriesUntilHint 2>/dev/null || echo "not set")
    [[ "$sh" == "0" || "$sh" == "not set" ]] && record_check "Access & Auth" "Password Hints" "PASS" "Password hints disabled" "" 2 "important" \
        || record_check "Access & Auth" "Password Hints" "WARN" "Password hints shown after ${sh} attempts" "sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0" 2 "important"

    local lw; lw=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null || echo "not set")
    [[ "$lw" == "1" ]] && record_check "Access & Auth" "Login Window: Name+Password" "PASS" "Login requires name+password — user list hidden" "" 2 "recommended" \
        || record_check "Access & Auth" "Login Window: Name+Password" "WARN" "Login shows user list — reveals account names" "sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true" 2 "recommended"

    local ds; ds=$(pmset -g 2>/dev/null | grep "displaysleep" | awk '{print $2}' || echo "0")
    if [[ "$ds" -le 5 && "$ds" -gt 0 ]]; then record_check "Access & Auth" "Display Sleep" "PASS" "Display sleeps after ${ds} min" "" 2 "important"
    elif [[ "$ds" == "0" ]]; then record_check "Access & Auth" "Display Sleep" "WARN" "Display never sleeps" "sudo pmset -a displaysleep 2" 2 "important"
    else record_check "Access & Auth" "Display Sleep" "WARN" "Display sleeps after ${ds} min — 2-5 min recommended" "sudo pmset -a displaysleep 2" 2 "important"; fi

    local rl=""
    [[ "$HAS_SUDO" == true ]] && rl=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "")
    if echo "$rl" | grep -qi "off"; then record_check "Access & Auth" "Remote Login (SSH)" "PASS" "SSH disabled" "" 3 "important"
    elif echo "$rl" | grep -qi "on"; then record_check "Access & Auth" "Remote Login (SSH)" "FAIL" "SSH enabled — remote terminal access open" "sudo systemsetup -setremotelogin off" 3 "important"
    else record_check "Access & Auth" "Remote Login (SSH)" "SKIP" "Could not check" "" 3 "important"; fi

    local st; st=$(sudo cat /etc/sudoers 2>/dev/null | grep "timestamp_timeout" || echo "default (5 min)")
    record_check "Access & Auth" "Sudo Timeout" "WARN" "Sudo timeout: ${st}. Consider reducing to 0-1 min." "Add via visudo: Defaults timestamp_timeout=1" 1 "recommended"

    local fm; fm=$(defaults read com.apple.FindMyMac FMMEnabled 2>/dev/null || echo "not set")
    if [[ "$fm" == "1" ]] || nvram -x -p 2>/dev/null | grep -q "fmm-mobileme-token-FMM"; then
        record_check "Access & Auth" "Find My Mac" "PASS" "Find My Mac enabled" "" 3 "important"
    else
        record_check "Access & Auth" "Find My Mac" "WARN" "Find My Mac status unknown. Check: System Settings → Apple ID → Find My" "" 3 "important"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. APPLICATION SECURITY
# ══════════════════════════════════════════════════════════════════════════════
check_application_security() {
    print_section "5" "APPLICATION SECURITY"

    # Launch Agents (user)
    local ua_dir="${HOME}/Library/LaunchAgents"; local sua=()
    if [[ -d "$ua_dir" ]]; then
        while IFS= read -r a; do [[ -z "$a" ]] && continue; local b; b=$(basename "$a"); is_trusted "$b" || sua+=("$b"); done < <(find "$ua_dir" -name "*.plist" 2>/dev/null)
    fi
    [[ ${#sua[@]} -eq 0 ]] && record_check "Application Security" "User Launch Agents" "PASS" "No suspicious user Launch Agents" "" 3 "important" \
        || record_check "Application Security" "User Launch Agents" "WARN" "Non-standard agents: $(printf ", %s" "${sua[@]}" | cut -c3-)" "ls -la ~/Library/LaunchAgents/" 3 "important"

    # Launch Agents (system)
    local sa_dir="/Library/LaunchAgents"; local ssa=()
    if [[ -d "$sa_dir" ]]; then
        while IFS= read -r a; do [[ -z "$a" ]] && continue; local b; b=$(basename "$a"); is_trusted "$b" || ssa+=("$b"); done < <(find "$sa_dir" -name "*.plist" 2>/dev/null)
    fi
    [[ ${#ssa[@]} -eq 0 ]] && record_check "Application Security" "System Launch Agents" "PASS" "No suspicious system Launch Agents" "" 3 "important" \
        || record_check "Application Security" "System Launch Agents" "WARN" "Non-standard system agents: $(printf ", %s" "${ssa[@]}" | cut -c3-)" "ls -la /Library/LaunchAgents/" 3 "important"

    # Launch Daemons
    local sd_dir="/Library/LaunchDaemons"; local ssd=()
    if [[ -d "$sd_dir" ]]; then
        while IFS= read -r d; do [[ -z "$d" ]] && continue; local b; b=$(basename "$d"); is_trusted "$b" || ssd+=("$b"); done < <(find "$sd_dir" -name "*.plist" 2>/dev/null)
    fi
    [[ ${#ssd[@]} -eq 0 ]] && record_check "Application Security" "System Launch Daemons" "PASS" "No suspicious Launch Daemons" "" 3 "important" \
        || record_check "Application Security" "System Launch Daemons" "WARN" "Non-standard daemons: $(printf ", %s" "${ssd[@]}" | cut -c3-)" "ls -la /Library/LaunchDaemons/" 3 "important"

    local li; li=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
    [[ -n "$li" && "$li" != "" ]] && record_check "Application Security" "Login Items" "WARN" "Login Items: ${li}" "System Settings → General → Login Items" 2 "recommended" \
        || record_check "Application Security" "Login Items" "PASS" "No user Login Items" "" 2 "recommended"

    local gk; gk=$(spctl --status 2>/dev/null || echo "")
    if echo "$gk" | grep -q "disabled"; then
        record_check "Application Security" "Gatekeeper: Allow Anywhere" "FAIL" "Gatekeeper fully disabled — any app can run" "sudo spctl --master-enable" 4 "critical"
    else
        record_check "Application Security" "Gatekeeper: Allow Anywhere" "PASS" "Gatekeeper active — signed apps only" "" 4 "critical"
    fi

    local qc; qc=$(find ~/Downloads -maxdepth 1 -xattr 2>/dev/null | xargs -I{} xattr -l {} 2>/dev/null | grep -c "com.apple.quarantine" || echo "0")
    [[ "$qc" -gt 0 ]] && record_check "Application Security" "Quarantine (Downloads)" "WARN" "${qc} quarantined files in ~/Downloads" "" 1 "recommended" \
        || record_check "Application Security" "Quarantine (Downloads)" "PASS" "No quarantined files in ~/Downloads" "" 1 "recommended"

    local ot=()
    [[ -d "/Applications/BlockBlock Helper.app" || -d "/Applications/BlockBlock.app" ]] && ot+=("BlockBlock")
    [[ -d "/Applications/OverSight.app" ]] && ot+=("OverSight")
    [[ -d "/Applications/KnockKnock.app" ]] && ot+=("KnockKnock")
    [[ -d "/Applications/RansomWhere.app" ]] && ot+=("RansomWhere?")
    [[ -d "/Applications/LuLu.app" ]] && ot+=("LuLu")
    if [[ ${#ot[@]} -gt 0 ]]; then
        record_check "Application Security" "Security Tools" "PASS" "Installed: $(printf ", %s" "${ot[@]}" | cut -c3-)" "" 2 "recommended"
    else
        record_check "Application Security" "Security Tools" "WARN" "No Objective-See tools found. Free open-source recommendations: LuLu (outbound firewall), BlockBlock (persistence monitor), KnockKnock (persistence audit), OverSight (camera/mic alerts)" "https://objective-see.org/tools.html" 2 "recommended"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 6. PERFORMANCE & HEALTH
# ══════════════════════════════════════════════════════════════════════════════
check_performance_health() {
    print_section "6" "PERFORMANCE & HEALTH"

    local vm; vm=$(vm_stat 2>/dev/null)
    local pf; pf=$(echo "$vm" | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
    local pa; pa=$(echo "$vm" | awk '/Pages active/ {gsub(/\./,"",$3); print $3}')
    local pi; pi=$(echo "$vm" | awk '/Pages inactive/ {gsub(/\./,"",$3); print $3}')
    local pw; pw=$(echo "$vm" | awk '/Pages wired/ {gsub(/\./,"",$4); print $4}')
    local pc; pc=$(echo "$vm" | awk '/Pages occupied by compressor/ {gsub(/\./,"",$5); print $5}')
    local tmb; tmb=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
    local tmg; tmg=$(echo "scale=1; $tmb / 1073741824" | bc 2>/dev/null || echo "N/A")
    local up=$((${pa:-0} + ${pw:-0} + ${pc:-0}))
    local tp=$((up + ${pf:-0} + ${pi:-0}))
    if [[ "$tp" -gt 0 ]]; then
        local mp=$((up * 100 / tp))
        if [[ "$mp" -lt 75 ]]; then record_check "Performance" "Memory Pressure" "PASS" "Memory: ~${mp}% (RAM: ${tmg} GB)" "" 2 "recommended"
        elif [[ "$mp" -lt 90 ]]; then record_check "Performance" "Memory Pressure" "WARN" "High memory: ~${mp}% (RAM: ${tmg} GB)" "" 2 "recommended"
        else record_check "Performance" "Memory Pressure" "FAIL" "Critical memory: ~${mp}% (RAM: ${tmg} GB)" "" 2 "recommended"; fi
    fi

    local si; si=$(sysctl vm.swapusage 2>/dev/null || echo "")
    local su; su=$(echo "$si" | awk '{for(i=1;i<=NF;i++) if ($i=="used") print $(i+2)}' | sed 's/M//')
    if [[ -n "$su" ]]; then
        local sv; sv=$(echo "$su" | sed 's/\..*//')
        [[ "${sv:-0}" -lt 1024 ]] && record_check "Performance" "Swap" "PASS" "Swap: ${su}MB" "" 1 "recommended" \
            || record_check "Performance" "Swap" "WARN" "Swap: ${su}MB — high usage, possible RAM shortage" "" 1 "recommended"
    fi

    local du_out; du_out=$(df -H / 2>/dev/null | tail -1)
    local dp; dp=$(echo "$du_out" | awk '{print $5}' | sed 's/%//')
    local da; da=$(echo "$du_out" | awk '{print $4}')
    if [[ "${dp:-0}" -lt 80 ]]; then record_check "Performance" "Disk Space" "PASS" "Disk: ${dp}% used, ${da} free" "" 2 "important"
    elif [[ "${dp:-0}" -lt 95 ]]; then record_check "Performance" "Disk Space" "WARN" "Disk: ${dp}% used, ${da} free" "" 2 "important"
    else record_check "Performance" "Disk Space" "FAIL" "Disk: ${dp}% used, ${da} free — critically low" "" 2 "important"; fi

    local cs; cs=$(du -sh ~/Library/Caches/ 2>/dev/null | awk '{print $1}' || echo "N/A")
    record_check "Performance" "User Caches" "WARN" "~/Library/Caches/: ${cs}" "rm -rf ~/Library/Caches/* (apps will recreate caches)" 1 "recommended"

    local sn; sn=$(tmutil listlocalsnapshotdates 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    [[ "${sn:-0}" -gt 10 ]] && record_check "Performance" "TM Snapshots" "WARN" "${sn} local snapshots" "tmutil thinlocalsnapshots / \$((\$(date +%s)-86400)) 1" 1 "recommended" \
        || record_check "Performance" "TM Snapshots" "PASS" "Snapshots: ${sn}" "" 1 "recommended"

    local bi; bi=$(pmset -g batt 2>/dev/null || echo "")
    if echo "$bi" | grep -q "InternalBattery"; then
        local bp; bp=$(echo "$bi" | grep -o '[0-9]*%' | head -1 | sed 's/%//')
        local bc; bc=$(system_profiler SPPowerDataType 2>/dev/null | grep "Condition" | awk -F': ' '{print $2}' || echo "Unknown")
        local cc; cc=$(system_profiler SPPowerDataType 2>/dev/null | grep "Cycle Count" | awk -F': ' '{print $2}' || echo "N/A")
        [[ "$bc" == "Normal" ]] && record_check "Performance" "Battery Health" "PASS" "Battery: ${bc}, ${bp}%, ${cc} cycles" "" 1 "recommended" \
            || record_check "Performance" "Battery Health" "WARN" "Battery: ${bc}, ${bp}%, ${cc} cycles" "" 1 "recommended"

        local oc; oc=$(defaults read com.apple.smartcharging isEnabled 2>/dev/null || echo "not set")
        [[ "$oc" == "1" || "$oc" == "not set" ]] && record_check "Performance" "Optimized Charging" "PASS" "Optimized charging active" "" 1 "recommended" \
            || record_check "Performance" "Optimized Charging" "WARN" "Optimized charging disabled" "System Settings → Battery → Optimized Battery Charging" 1 "recommended"
    fi

    local ut; ut=$(uptime 2>/dev/null | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')
    record_check "Performance" "Uptime" "PASS" "Uptime: ${ut}" "" 0 "info"
}

# ══════════════════════════════════════════════════════════════════════════════
# TCC PERMISSIONS
# ══════════════════════════════════════════════════════════════════════════════
check_tcc_permissions() {
    [[ "$HAS_SUDO" != true ]] && return
    print_section "+" "TCC PERMISSIONS AUDIT"
    local tcc="/Library/Application Support/com.apple.TCC/TCC.db"
    [[ ! -f "$tcc" ]] && { record_check "TCC Audit" "TCC Database" "SKIP" "TCC.db not found" "" 0 "info"; return; }

    local svcs=("kTCCServiceCamera:Camera" "kTCCServiceMicrophone:Microphone" "kTCCServiceScreenCapture:Screen Recording" "kTCCServiceSystemPolicyAllFiles:Full Disk Access" "kTCCServiceAccessibility:Accessibility" "kTCCServiceListenEvent:Input Monitoring")
    for sp in "${svcs[@]}"; do
        local sid="${sp%%:*}" sname="${sp##*:}"
        local apps; apps=$(sudo sqlite3 "$tcc" "SELECT client FROM access WHERE service='${sid}' AND auth_value=2;" 2>/dev/null || echo "")
        if [[ -n "$apps" ]]; then
            local ac; ac=$(echo "$apps" | wc -l | tr -d ' ')
            local al; al=$(echo "$apps" | tr '\n' ', ' | sed 's/,$//')
            record_check "TCC Audit" "TCC: ${sname}" "WARN" "${ac} apps with access: ${al}" "System Settings → Privacy & Security → ${sname}" 2 "important"
        else
            record_check "TCC Audit" "TCC: ${sname}" "PASS" "No apps with ${sname} access" "" 2 "important"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════
calculate_score() {
    local tw=0 ew=0
    for r in "${RESULTS_JSON[@]}"; do
        local w; w=$(echo "$r" | sed 's/.*"weight":\([0-9]*\).*/\1/')
        local s; s=$(echo "$r" | sed 's/.*"status":"\([A-Z]*\)".*/\1/')
        [[ "$s" == "SKIP" ]] && continue
        tw=$((tw + w))
        [[ "$s" == "PASS" ]] && ew=$((ew + w))
        [[ "$s" == "WARN" ]] && ew=$((ew + w / 2))
    done
    [[ "$tw" -gt 0 ]] && echo $((ew * 100 / tw)) || echo 0
}

generate_html_report() {
    local score; score=$(calculate_score)
    local sc="#22c55e" sl="Excellent"
    [[ "$score" -lt 50 ]] && sc="#ef4444" && sl="Critical"
    [[ "$score" -ge 50 && "$score" -lt 70 ]] && sc="#f59e0b" && sl="Needs Attention"
    [[ "$score" -ge 70 && "$score" -lt 85 ]] && sc="#3b82f6" && sl="Good"

    local circ=452 doff=$((452 - (452 * score / 100)))

    cat > "$REPORT_FILE" << HTMLALL
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>macOS Security Audit</title>
<style>:root{--bg:#0a0a0b;--bg2:#111113;--bg3:#16161a;--bg4:#1c1c21;--br:#252529;--t1:#e4e4e7;--t2:#a1a1aa;--t3:#71717a;--ac:#a78bfa;--pass:#22c55e;--passbg:rgba(34,197,94,.08);--fail:#ef4444;--failbg:rgba(239,68,68,.08);--warn:#f59e0b;--warnbg:rgba(245,158,11,.08);--skip:#52525b;--skipbg:rgba(82,82,91,.08);--sans:-apple-system,BlinkMacSystemFont,'SF Pro Display',system-ui,sans-serif;--mono:'SF Mono','Fira Code','Consolas',monospace}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--t1);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}.c{max-width:960px;margin:0 auto;padding:40px 24px 80px}.hd{text-align:center;margin-bottom:48px;padding-bottom:32px;border-bottom:1px solid var(--br)}.hd h1{font-size:28px;font-weight:600;letter-spacing:-.5px;margin-bottom:16px}.mg{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 24px;font-size:13px;color:var(--t2);font-family:var(--mono)}.mg span{opacity:.6}.mg strong{color:var(--t1);opacity:1;font-weight:500}.ss{display:flex;flex-direction:column;align-items:center;margin:40px 0}.sr{position:relative;width:160px;height:160px}.sr svg{transform:rotate(-90deg);width:160px;height:160px}.sr circle{fill:none;stroke-width:8;stroke-linecap:round}.sbg{stroke:var(--br)}.sv{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}.sn{font-size:42px;font-weight:700;letter-spacing:-2px;line-height:1}.sla{font-size:12px;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-top:4px}.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:32px 0 48px}.sc{background:var(--bg3);border:1px solid var(--br);border-radius:10px;padding:16px;text-align:center}.sc .ct{font-size:28px;font-weight:700;letter-spacing:-1px}.sc .lb{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--t3);margin-top:4px}.sec{margin-bottom:32px}.sh{display:flex;align-items:center;gap:12px;padding:12px 0;margin-bottom:8px;border-bottom:1px solid var(--br)}.sh h2{font-size:16px;font-weight:600}.snm{background:var(--bg4);color:var(--t3);font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;font-family:var(--mono)}.ci{display:grid;grid-template-columns:72px 1fr;padding:12px 0;border-bottom:1px solid var(--bg4);align-items:start}.ci:last-child{border-bottom:none}.sb{font-size:11px;font-weight:600;font-family:var(--mono);text-transform:uppercase;letter-spacing:.5px;padding:3px 8px;border-radius:4px;text-align:center;width:fit-content}.sp{color:var(--pass);background:var(--passbg)}.sf{color:var(--fail);background:var(--failbg)}.sw{color:var(--warn);background:var(--warnbg)}.sk{color:var(--skip);background:var(--skipbg)}.cb h3{font-size:14px;font-weight:500;margin-bottom:4px}.cd{font-size:13px;color:var(--t2);line-height:1.5}.cf{margin-top:6px;padding:6px 10px;background:var(--bg2);border:1px solid var(--br);border-radius:6px;font-family:var(--mono);font-size:12px;color:var(--ac);word-break:break-all;cursor:pointer;transition:border-color .2s}.cf:hover{border-color:var(--ac)}.qf{margin-top:48px;padding:24px;background:var(--bg3);border:1px solid var(--br);border-radius:12px}.qf h2{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--fail)}.qb{background:var(--bg);border:1px solid var(--br);border-radius:8px;padding:16px;font-family:var(--mono);font-size:12px;line-height:1.8;color:var(--t1);white-space:pre-wrap;word-break:break-all;cursor:pointer;position:relative}.qb:hover{border-color:var(--ac)}.ch{position:absolute;top:8px;right:12px;font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:1px}.mr{margin-top:32px;padding:24px;background:var(--bg3);border:1px solid var(--br);border-radius:12px}.mr h2{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--ac)}.mr ul{list-style:none;padding:0}.mr li{padding:8px 0;border-bottom:1px solid var(--bg4);font-size:13px;color:var(--t2);line-height:1.6}.mr li:last-child{border-bottom:none}.mr li strong{color:var(--t1)}.ft{text-align:center;margin-top:48px;padding-top:24px;border-top:1px solid var(--br);font-size:12px;color:var(--t3)}@media(max-width:640px){.sg{grid-template-columns:repeat(2,1fr)}.ci{grid-template-columns:64px 1fr}.mg{grid-template-columns:1fr}}</style></head><body><div class="c">
<div class="hd"><h1>macOS Security Audit</h1><div class="mg">
<div><span>Host:</span> <strong>${HOSTNAME_VAL}</strong></div><div><span>macOS:</span> <strong>${MACOS_VERSION} (${MACOS_BUILD})</strong></div>
<div><span>Model:</span> <strong>${HARDWARE_MODEL}</strong></div><div><span>Chip:</span> <strong>${CHIP}</strong></div>
<div><span>Arch:</span> <strong>${ARCH}</strong></div><div><span>Date:</span> <strong>${AUDIT_DATE}</strong></div>
<div><span>Serial:</span> <strong>${SERIAL}</strong></div><div><span>Script:</span> <strong>v${SCRIPT_VERSION}</strong></div></div></div>
<div class="ss"><div class="sr"><svg viewBox="0 0 160 160"><circle class="sbg" cx="80" cy="80" r="72"/><circle cx="80" cy="80" r="72" stroke="${sc}" stroke-dasharray="${circ}" stroke-dashoffset="${doff}"/></svg><div class="sv"><div class="sn" style="color:${sc}">${score}</div><div class="sla">${sl}</div></div></div></div>
<div class="sg"><div class="sc"><div class="ct" style="color:var(--pass)">${PASS_COUNT}</div><div class="lb">Pass</div></div><div class="sc"><div class="ct" style="color:var(--fail)">${FAIL_COUNT}</div><div class="lb">Fail</div></div><div class="sc"><div class="ct" style="color:var(--warn)">${WARN_COUNT}</div><div class="lb">Warn</div></div><div class="sc"><div class="ct" style="color:var(--skip)">${SKIP_COUNT}</div><div class="lb">Skip</div></div></div>
HTMLALL

    local cc="" snum=0
    for r in "${RESULTS_JSON[@]}"; do
        local ct nm st dt fx
        ct=$(echo "$r" | sed 's/.*"category":"\([^"]*\)".*/\1/')
        nm=$(echo "$r" | sed 's/.*"name":"\([^"]*\)".*/\1/')
        st=$(echo "$r" | sed 's/.*"status":"\([^"]*\)".*/\1/')
        dt=$(echo "$r" | sed 's/.*"detail":"\([^"]*\)".*/\1/')
        fx=$(echo "$r" | sed 's/.*"fix":"\([^"]*\)".*/\1/')
        if [[ "$ct" != "$cc" ]]; then
            [[ -n "$cc" ]] && echo "</div>" >> "$REPORT_FILE"
            cc="$ct"; snum=$((snum+1))
            echo "<div class=\"sec\"><div class=\"sh\"><span class=\"snm\">${snum}</span><h2>${ct}</h2></div>" >> "$REPORT_FILE"
        fi
        local scl="sp"; [[ "$st" == "FAIL" ]] && scl="sf"; [[ "$st" == "WARN" ]] && scl="sw"; [[ "$st" == "SKIP" ]] && scl="sk"
        echo "<div class=\"ci\"><div><span class=\"sb ${scl}\">${st}</span></div><div class=\"cb\"><h3>${nm}</h3><div class=\"cd\">${dt}</div>" >> "$REPORT_FILE"
        [[ -n "$fx" && "$fx" != "" ]] && echo "<div class=\"cf\" onclick=\"navigator.clipboard.writeText(this.textContent.trim())\">${fx}</div>" >> "$REPORT_FILE"
        echo "</div></div>" >> "$REPORT_FILE"
    done
    [[ -n "$cc" ]] && echo "</div>" >> "$REPORT_FILE"

    if [[ ${#QUICK_FIXES[@]} -gt 0 ]]; then
        echo '<div class="qf"><h2>⚡ Quick Fix</h2><div class="qb" onclick="navigator.clipboard.writeText(this.textContent.replace('"'"'Click to copy all'"'"','"'"''"'"').trim())"><span class="ch">Click to copy all</span>' >> "$REPORT_FILE"
        for q in "${QUICK_FIXES[@]}"; do echo "${q%%|*}"; echo "${q##*|}"; echo ""; done >> "$REPORT_FILE"
        echo '</div></div>' >> "$REPORT_FILE"
    fi

    cat >> "$REPORT_FILE" << 'HTMLEND'
<div class="mr"><h2>📋 Manual Recommendations</h2><ul>
<li><strong>VPN:</strong> Use a no-log VPN at all times (Mullvad, ProtonVPN, IVPN). Enable kill switch, use WireGuard protocol, enable DNS leak protection.</li>
<li><strong>Browser:</strong> Use a privacy-focused browser (DuckDuckGo, Firefox with arkenfox, Brave, LibreWolf). Disable WebRTC in about:config: media.peerconnection.enabled=false</li>
<li><strong>Separate Profile:</strong> Use a dedicated browser for sensitive operations (crypto, banking) — never mix with everyday browsing.</li>
<li><strong>Password Manager:</strong> Use Bitwarden or 1Password. Master password: 4+ diceware words, unique. Enable TOTP or FIDO2.</li>
<li><strong>MFA:</strong> Critical accounts — FIDO2 hardware key (YubiKey). Others — TOTP (Ente Auth). Disable SMS MFA everywhere (SIM swap risk).</li>
<li><strong>Apple ID:</strong> Enable Advanced Data Protection (E2E iCloud encryption). Bind YubiKey to Apple ID.</li>
<li><strong>Messaging:</strong> Signal for sensitive conversations. Enable disappearing messages, Registration Lock, Screen Lock.</li>
<li><strong>Security Tools:</strong> LuLu (outbound firewall), BlockBlock (persistence monitor), KnockKnock (persistence audit), OverSight (camera/mic). All free: https://objective-see.org/tools.html</li>
<li><strong>Backup:</strong> Time Machine to encrypted external disk. Test restore quarterly.</li>
<li><strong>Leak Tests:</strong> Regularly check: dnsleaktest.com (extended), browserleaks.com/webrtc</li>
</ul></div>
HTMLEND

    echo "<div class=\"ft\">macOS Security Audit Tool v${SCRIPT_VERSION} · ${AUDIT_DATE} · ${HOSTNAME_VAL}</div></div>" >> "$REPORT_FILE"
    echo '<script>document.querySelectorAll(".cf").forEach(e=>e.addEventListener("click",function(){navigator.clipboard.writeText(this.textContent.trim()).then(()=>{this.style.borderColor="var(--pass)";setTimeout(()=>this.style.borderColor="",800)})}))</script></body></html>' >> "$REPORT_FILE"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
    clear; print_banner; HAS_SUDO=false; request_sudo
    echo ""; echo -e "${BOLD}Running audit...${NC}"
    check_system_integrity; check_network_security; check_privacy_controls
    check_access_auth; check_application_security; check_performance_health; check_tcc_permissions
    echo ""; echo -e "${BOLD}${CYAN}Generating HTML report...${NC}"; generate_html_report
    local score; score=$(calculate_score)
    echo ""; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  AUDIT RESULTS${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "  Security Score: ${BOLD}${score}/100${NC}"
    echo -e "  ${GREEN}PASS: ${PASS_COUNT}${NC}  ${RED}FAIL: ${FAIL_COUNT}${NC}  ${YELLOW}WARN: ${WARN_COUNT}${NC}  ${DIM}SKIP: ${SKIP_COUNT}${NC}"
    echo -e "  Total checks: ${TOTAL_CHECKS}"; echo ""
    echo -e "  HTML report: ${BOLD}${REPORT_FILE}${NC}"; echo ""
    open "$REPORT_FILE" 2>/dev/null || true
    [[ -n "${SUDO_KEEPER_PID:-}" ]] && kill "$SUDO_KEEPER_PID" 2>/dev/null || true
}
main "$@"
