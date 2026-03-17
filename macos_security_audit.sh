#!/bin/bash
set -uo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  macOS Security Audit Tool v1.2.1                                           ║
# ║  Comprehensive macOS security audit with HTML report                        ║
# ║  Compatibility: macOS 12+ (Monterey), Intel & Apple Silicon                 ║
# ║  VPN-aware | Outbound Firewall-aware | Privacy Browser-aware                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

SCRIPT_VERSION="1.2.1"
AUDIT_DATE=$(date "+%Y-%m-%d %H:%M:%S")
AUDIT_TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
HOSTNAME_VAL=$(hostname)
MACOS_VERSION=$(sw_vers -productVersion)
MACOS_BUILD=$(sw_vers -buildVersion)
HARDWARE_MODEL=$(sysctl -n hw.model 2>/dev/null || echo "Unknown")
ARCH=$(uname -m)
SERIAL=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $NF}' || echo "N/A")
CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")

REPORT_DIR="${HOME}/Desktop"
REPORT_FILE="${REPORT_DIR}/security_audit_${AUDIT_TIMESTAMP}.html"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TOTAL_CHECKS=0; PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; SKIP_COUNT=0
declare -a RESULTS_CATEGORY=()
declare -a RESULTS_NAME=()
declare -a RESULTS_STATUS=()
declare -a RESULTS_DETAIL=()
declare -a RESULTS_FIX=()
declare -a RESULTS_WEIGHT=()
declare -a QUICK_FIXES=()

TRUSTED_PATTERNS=(
    "com.apple." "com.mullvad" "com.nordvpn" "com.expressvpn"
    "ch.protonvpn" "com.protonvpn" "com.wireguard" "com.openvpn"
    "com.surfshark" "com.privateinternetaccess" "com.cloudflare.warp"
    "com.cisco.anyconnect" "com.objective-see" "com.duckduckgo"
    "com.littlesnitch" "at.obdev.littlesnitch"
)

VPN_PROCESS_PATTERNS=(
    "mullvad:Mullvad VPN" "nordvpn:NordVPN" "expressvpn:ExpressVPN"
    "protonvpn:ProtonVPN" "wireguard:WireGuard" "openvpn:OpenVPN"
    "surfshark:Surfshark" "cloudflare-warp:Cloudflare WARP"
)

VPN_DNS_PATTERNS=("10.64.0" "100.64.0" "10.124.0" "10.2.0.1" "103.86.96" "103.86.99")
SAFE_PUBLIC_DNS=("1.1.1.1" "1.0.0.1" "9.9.9.9" "149.112.112.112" "208.67.222.222" "208.67.220.220")

# ══════════════════════════════════════════════════════════════════════════════
print_banner() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║       macOS Security Audit Tool v${SCRIPT_VERSION}                ║${NC}"
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
    local category="$1" name="$2" status="$3" detail="$4" fix="${5:-}" weight="${6:-1}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}✓ PASS${NC}  ${name}" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "  ${RED}✗ FAIL${NC}  ${name}"
              if [[ -n "$fix" ]]; then echo -e "         ${DIM}Fix: ${fix}${NC}"; fi ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)); echo -e "  ${YELLOW}⚠ WARN${NC}  ${name}" ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)); echo -e "  ${DIM}○ SKIP${NC}  ${name}" ;;
    esac
    RESULTS_CATEGORY+=("$category")
    RESULTS_NAME+=("$name")
    RESULTS_STATUS+=("$status")
    RESULTS_DETAIL+=("$detail")
    RESULTS_FIX+=("$fix")
    RESULTS_WEIGHT+=("$weight")
    if [[ "$status" == "FAIL" && -n "$fix" ]]; then
        QUICK_FIXES+=("# ${name}|${fix}")
    fi
}

is_trusted() {
    for p in "${TRUSTED_PATTERNS[@]}"; do
        if [[ "$1" == *"$p"* ]]; then return 0; fi
    done
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
    if [[ "$dns" == "127."* || "$dns" == "::1" || "$dns" == "fe80:"* ]]; then return 0; fi
    for p in "${VPN_DNS_PATTERNS[@]}"; do
        if [[ "$dns" == ${p}* ]]; then return 0; fi
    done
    for s in "${SAFE_PUBLIC_DNS[@]}"; do
        if [[ "$dns" == "$s" ]]; then return 0; fi
    done
    return 1
}

read_default() {
    local val
    val=$(defaults read "$@" 2>/dev/null) || val="NOT_SET"
    echo "$val"
}

# Проверка вывода socketfilterfw: macOS возвращает разные строки в зависимости от State
# State=0: "disabled"
# State=1: "enabled"  
# State=2: "blocking all non-essential incoming connections"
# Stealth: "stealth mode is on" / "stealth mode is off"
# Поэтому проверяем на ОТСУТСТВИЕ "disabled" и "off" вместо наличия "enabled"
fw_is_on() {
    local output="$1"
    if [[ -z "$output" ]]; then return 1; fi
    # Если содержит "disabled" или "is off" — выключено
    if echo "$output" | grep -qi "disabled\|is off"; then return 1; fi
    # Если содержит "enabled" или "blocking" или "is on" — включено
    if echo "$output" | grep -qi "enabled\|blocking\|is on"; then return 0; fi
    return 1
}

request_sudo() {
    echo -e "${YELLOW}Some checks require sudo (Firewall, TCC, system settings).${NC}"
    echo -e "${DIM}Password is requested once and cached for the audit duration.${NC}"
    echo ""
    if sudo -v 2>/dev/null; then
        HAS_SUDO=true
        while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
        SUDO_KEEPER_PID=$!
    else
        echo -e "${YELLOW}⚠ sudo unavailable. Some checks will be skipped.${NC}"
        HAS_SUDO=false
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. SYSTEM INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
check_system_integrity() {
    print_section "1" "SYSTEM INTEGRITY"

    local val
    val=$(csrutil status 2>/dev/null || echo "")
    if echo "$val" | grep -q "enabled"; then
        record_check "System Integrity" "SIP (System Integrity Protection)" "PASS" "SIP is enabled" "" 5
    else
        record_check "System Integrity" "SIP (System Integrity Protection)" "FAIL" "SIP is disabled — system vulnerable to rootkits" "Reboot to Recovery Mode → Terminal → csrutil enable" 5
    fi

    val=$(fdesetup status 2>/dev/null || echo "")
    if echo "$val" | grep -q "FileVault is On"; then
        record_check "System Integrity" "FileVault 2 (Disk Encryption)" "PASS" "FileVault is enabled" "" 5
    elif echo "$val" | grep -q "Encryption in progress"; then
        record_check "System Integrity" "FileVault 2 (Disk Encryption)" "WARN" "Encryption in progress" "" 5
    else
        record_check "System Integrity" "FileVault 2 (Disk Encryption)" "FAIL" "Disk not encrypted — data accessible with physical access" "sudo fdesetup enable" 5
    fi

    val=$(spctl --status 2>/dev/null || echo "")
    if echo "$val" | grep -q "assessments enabled"; then
        record_check "System Integrity" "Gatekeeper" "PASS" "Gatekeeper is active" "" 4
    else
        record_check "System Integrity" "Gatekeeper" "FAIL" "Gatekeeper disabled — unsigned apps can run" "sudo spctl --master-enable" 4
    fi

    val=$(read_default /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates)
    if [[ "$val" == "1" ]]; then
        record_check "System Integrity" "Automatic macOS Updates" "PASS" "Enabled" "" 3
    else
        record_check "System Integrity" "Automatic macOS Updates" "FAIL" "Disabled" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true" 3
    fi

    val=$(read_default /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall)
    if [[ "$val" == "1" ]]; then
        record_check "System Integrity" "Rapid Security Responses" "PASS" "Enabled" "" 4
    else
        record_check "System Integrity" "Rapid Security Responses" "FAIL" "Disabled — critical patches not auto-installed" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true" 4
    fi

    val=$(read_default /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled)
    if [[ "$val" == "1" ]]; then
        record_check "System Integrity" "Automatic Update Check" "PASS" "Enabled" "" 2
    else
        record_check "System Integrity" "Automatic Update Check" "FAIL" "Disabled" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true" 2
    fi

    val=$(read_default /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload)
    if [[ "$val" == "1" ]]; then
        record_check "System Integrity" "Automatic Update Download" "PASS" "Enabled" "" 2
    else
        record_check "System Integrity" "Automatic Update Download" "FAIL" "Disabled" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true" 2
    fi

    val=$(read_default /Library/Preferences/com.apple.commerce AutoUpdate)
    if [[ "$val" == "1" ]]; then
        record_check "System Integrity" "App Store Auto-Update" "PASS" "Enabled" "" 1
    else
        record_check "System Integrity" "App Store Auto-Update" "WARN" "Not enabled" "sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true" 1
    fi

    if [[ "$ARCH" == "x86_64" ]]; then
        if [[ -f "/usr/libexec/firmwarecheckers/eficheck/eficheck" ]]; then
            val=$(/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check 2>&1 || true)
            if echo "$val" | grep -qi "passed\|No changes"; then
                record_check "System Integrity" "EFI Firmware Integrity" "PASS" "Integrity check passed" "" 5
            elif echo "$val" | grep -qi "not supported\|error"; then
                record_check "System Integrity" "EFI Firmware Integrity" "SKIP" "Not supported on this Mac" "" 0
            else
                record_check "System Integrity" "EFI Firmware Integrity" "WARN" "Ambiguous result — manual check recommended" "" 5
            fi
        fi
    else
        record_check "System Integrity" "Secure Boot (Apple Silicon)" "PASS" "Full Security by default" "" 5
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. NETWORK SECURITY
# ══════════════════════════════════════════════════════════════════════════════
check_network_security() {
    print_section "2" "NETWORK SECURITY"

    # ── Firewall checks ──
    # macOS socketfilterfw возвращает разные строки:
    #   --getglobalstate: "enabled. (State = 1)" / "blocking all... (State = 2)" / "disabled. (State = 0)"
    #   --getstealthmode: "stealth mode is on" / "stealth mode is off"
    #   --getblockall: "blocking all non-essential..." / "Disabled..."
    # Используем fw_is_on() для надёжного парсинга
    if [[ "$HAS_SUDO" == true ]]; then
        local fw_out; fw_out=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "")
        if fw_is_on "$fw_out"; then
            record_check "Network Security" "Application Firewall" "PASS" "Firewall enabled" "" 4
        else
            record_check "Network Security" "Application Firewall" "FAIL" "Firewall disabled" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" 4
        fi

        local st_out; st_out=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "")
        if fw_is_on "$st_out"; then
            record_check "Network Security" "Firewall Stealth Mode" "PASS" "Stealth Mode enabled" "" 3
        else
            record_check "Network Security" "Firewall Stealth Mode" "FAIL" "Stealth Mode disabled — Mac responds to ping/port scan" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on" 3
        fi

        local ba_out; ba_out=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo "")
        if fw_is_on "$ba_out"; then
            record_check "Network Security" "Block All Incoming" "PASS" "All incoming blocked" "" 2
        else
            record_check "Network Security" "Block All Incoming" "WARN" "Service exceptions allowed" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on" 2
        fi
    else
        record_check "Network Security" "Application Firewall" "SKIP" "Requires sudo" "" 4
        record_check "Network Security" "Firewall Stealth Mode" "SKIP" "Requires sudo" "" 3
        record_check "Network Security" "Block All Incoming" "SKIP" "Requires sudo" "" 2
    fi

    # ── VPN ──
    local vpn_tunnel; vpn_tunnel=$(ifconfig 2>/dev/null | grep -c "utun" || echo "0")
    local detected_vpn; detected_vpn=$(detect_vpn)

    if [[ "$vpn_tunnel" -gt 0 && -n "$detected_vpn" ]]; then
        record_check "Network Security" "VPN Tunnel" "PASS" "VPN active (${detected_vpn})" "" 5
    elif [[ "$vpn_tunnel" -gt 0 ]]; then
        record_check "Network Security" "VPN Tunnel" "PASS" "VPN tunnel active (utun detected)" "" 5
    else
        record_check "Network Security" "VPN Tunnel" "WARN" "No VPN — traffic visible to ISP. Recommended: Mullvad, ProtonVPN, IVPN" "https://mullvad.net or https://protonvpn.com" 5
    fi

    # ── DNS ──
    local dns_servers; dns_servers=$(scutil --dns 2>/dev/null | grep "nameserver\[" | awk '{print $3}' | sort -u)
    local unsafe_dns=()
    local vpn_dns_found=false
    local has_dns=false

    if [[ -n "$dns_servers" ]]; then
        while IFS= read -r dns; do
            [[ -z "$dns" ]] && continue
            has_dns=true
            if is_safe_dns "$dns"; then
                for p in "${VPN_DNS_PATTERNS[@]}"; do
                    if [[ "$dns" == ${p}* ]]; then vpn_dns_found=true; break; fi
                done
            else
                unsafe_dns+=("$dns")
            fi
        done <<< "$dns_servers"
    fi

    if [[ "$has_dns" == false ]]; then
        record_check "Network Security" "DNS Security" "WARN" "Could not determine DNS servers" "" 5
    elif [[ ${#unsafe_dns[@]} -eq 0 && "$vpn_dns_found" == true ]]; then
        record_check "Network Security" "DNS Security" "PASS" "DNS through VPN — no leaks" "" 5
    elif [[ ${#unsafe_dns[@]} -eq 0 ]]; then
        record_check "Network Security" "DNS Security" "PASS" "DNS servers are safe (privacy-friendly or VPN)" "" 5
    else
        local ul; ul=$(printf ", %s" "${unsafe_dns[@]}"); ul="${ul:2}"
        if [[ "$vpn_tunnel" -gt 0 ]]; then
            record_check "Network Security" "DNS Security" "WARN" "VPN active but non-VPN DNS: ${ul} — possible leak" "Check DNS in VPN client" 5
        else
            record_check "Network Security" "DNS Security" "WARN" "ISP DNS: ${ul} — ISP sees all queries. Use VPN or 1.1.1.1/9.9.9.9" "networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1" 4
        fi
    fi

    # ── Default route ──
    local dr; dr=$(route -n get default 2>/dev/null | grep "interface:" | awk '{print $2}' || echo "")
    if [[ "$dr" == utun* ]]; then
        record_check "Network Security" "Default Route via VPN" "PASS" "Default route through VPN (${dr})" "" 4
    elif [[ "$vpn_tunnel" -gt 0 && -n "$dr" ]]; then
        record_check "Network Security" "Default Route" "WARN" "Route: ${dr} — VPN may use split tunneling" "" 3
    elif [[ -n "$dr" ]]; then
        record_check "Network Security" "Default Route" "WARN" "Route: ${dr} — no VPN, traffic visible to ISP" "" 3
    fi

    # ── Outbound Firewall ──
    local obfw_found=false obfw_name="" obfw_running=false
    if [[ -d "/Applications/LuLu.app" ]]; then
        obfw_found=true; obfw_name="LuLu"
        if pgrep -x "LuLu" >/dev/null 2>&1; then obfw_running=true; fi
    fi
    if [[ -d "/Applications/Little Snitch.app" || -d "/Library/Little Snitch" ]]; then
        obfw_found=true; obfw_name="${obfw_name:+${obfw_name} + }Little Snitch"
        if pgrep -f "Little Snitch" >/dev/null 2>&1; then obfw_running=true; fi
    fi
    if [[ "$obfw_found" == true && "$obfw_running" == true ]]; then
        record_check "Network Security" "Outbound Firewall" "PASS" "${obfw_name} active" "" 3
    elif [[ "$obfw_found" == true ]]; then
        record_check "Network Security" "Outbound Firewall" "WARN" "${obfw_name} installed but not running" "Launch from /Applications" 3
    else
        record_check "Network Security" "Outbound Firewall" "WARN" "No outbound firewall. Recommended: LuLu (free) or Little Snitch" "https://objective-see.org/products/lulu.html" 3
    fi

    # ── Sharing ──
    local sharing_services=("Remote Login:ssh" "Screen Sharing:screensharing" "File Sharing:smb" "Remote Management:remotemanagement" "Printer Sharing:printersharing" "Content Caching:contentcaching" "Remote Apple Events:remoteappleevents")
    for sp in "${sharing_services[@]}"; do
        local dn="${sp%%:*}" sn="${sp##*:}" is_on=false
        case "$sn" in
            ssh)
                if [[ "$HAS_SUDO" == true ]]; then
                    local ss; ss=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "")
                    if echo "$ss" | grep -qi "on"; then is_on=true; fi
                fi
                ;;
            *) if launchctl list 2>/dev/null | grep -qi "$sn"; then is_on=true; fi ;;
        esac
        if [[ "$is_on" == true ]]; then
            local fc=""
            if [[ "$sn" == "ssh" ]]; then fc="sudo systemsetup -setremotelogin off"
            else fc="System Settings → General → Sharing → disable ${dn}"; fi
            record_check "Network Security" "Sharing: ${dn}" "FAIL" "${dn} enabled — potential entry point" "$fc" 3
        else
            record_check "Network Security" "Sharing: ${dn}" "PASS" "${dn} disabled" "" 3
        fi
    done

    # ── AirDrop ──
    local ad; ad=$(read_default com.apple.sharingd DiscoverableMode)
    if [[ "$ad" == "Off" ]]; then
        record_check "Network Security" "AirDrop" "PASS" "AirDrop off" "" 2
    elif [[ "$ad" == "Contacts Only" ]]; then
        record_check "Network Security" "AirDrop" "PASS" "AirDrop: Contacts Only" "" 2
    else
        record_check "Network Security" "AirDrop" "WARN" "AirDrop open to everyone" "defaults write com.apple.sharingd DiscoverableMode -string 'Contacts Only'" 2
    fi

    # ── Bluetooth ──
    local bt; bt=$(read_default /Library/Preferences/com.apple.Bluetooth ControllerPowerState)
    if [[ "$bt" == "0" ]]; then
        record_check "Network Security" "Bluetooth" "PASS" "Bluetooth off" "" 1
    else
        record_check "Network Security" "Bluetooth" "WARN" "Bluetooth on — turn off when not in use" "" 1
    fi

    # ── Wi-Fi ──
    local nc; nc=$(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2 | grep -c "." 2>/dev/null || echo "0")
    if [[ "$nc" -gt 10 ]]; then
        record_check "Network Security" "Wi-Fi: Saved Networks" "WARN" "${nc} saved — remove unused (evil twin risk)" "networksetup -removepreferredwirelessnetwork en0 'NAME'" 2
    else
        record_check "Network Security" "Wi-Fi: Saved Networks" "PASS" "${nc} saved networks" "" 2
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. PRIVACY CONTROLS
# ══════════════════════════════════════════════════════════════════════════════
check_privacy_controls() {
    print_section "3" "PRIVACY CONTROLS"

    local val

    val=$(read_default /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit)
    if [[ "$val" == "0" ]]; then
        record_check "Privacy Controls" "Apple Analytics" "PASS" "Diagnostics disabled" "" 2
    else
        record_check "Privacy Controls" "Apple Analytics" "FAIL" "Diagnostics enabled" "sudo defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool false" 2
    fi

    val=$(read_default com.apple.CrashReporter DialogType)
    if [[ "$val" == "none" ]]; then
        record_check "Privacy Controls" "Crash Reporter" "PASS" "Silent" "" 1
    else
        record_check "Privacy Controls" "Crash Reporter" "WARN" "May send data" "defaults write com.apple.CrashReporter DialogType -string 'none'" 1
    fi

    val=$(read_default com.apple.AdLib forceLimitAdTracking)
    if [[ "$val" == "1" ]]; then
        record_check "Privacy Controls" "Personalized Ads" "PASS" "Limited" "" 2
    else
        record_check "Privacy Controls" "Personalized Ads" "FAIL" "Not limited" "defaults write com.apple.AdLib forceLimitAdTracking -bool true" 2
    fi

    val=$(read_default com.apple.assistant.support "Assistant Enabled")
    if [[ "$val" == "0" ]]; then
        record_check "Privacy Controls" "Siri" "PASS" "Disabled" "" 2
    else
        record_check "Privacy Controls" "Siri" "WARN" "Enabled — queries may go to Apple servers" "defaults write com.apple.assistant.support 'Assistant Enabled' -bool false" 2
    fi

    val=$(read_default com.apple.assistant.support "Siri Data Sharing Opt-In Status")
    if [[ "$val" == "2" || "$val" == "0" ]]; then
        record_check "Privacy Controls" "Siri Data Sharing" "PASS" "Disabled" "" 2
    elif [[ "$val" == "NOT_SET" ]]; then
        record_check "Privacy Controls" "Siri Data Sharing" "WARN" "Status unknown" "" 2
    else
        record_check "Privacy Controls" "Siri Data Sharing" "FAIL" "Enabled" "defaults write com.apple.assistant.support 'Siri Data Sharing Opt-In Status' -int 2" 2
    fi

    val=$(read_default com.apple.lookup.shared LookupSuggestionsDisabled)
    if [[ "$val" == "1" ]]; then
        record_check "Privacy Controls" "Spotlight Suggestions" "PASS" "Disabled" "" 2
    else
        record_check "Privacy Controls" "Spotlight Suggestions" "FAIL" "Sends queries to Apple" "defaults write com.apple.lookup.shared LookupSuggestionsDisabled -bool true" 2
    fi

    val=$(read_default com.apple.Safari UniversalSearchEnabled)
    if [[ "$val" == "0" ]]; then
        record_check "Privacy Controls" "Safari Suggestions" "PASS" "Disabled" "" 1
    else
        record_check "Privacy Controls" "Safari Suggestions" "WARN" "May send queries to Apple" "System Settings → Safari → Search → disable Suggestions" 1
    fi

    if [[ "$HAS_SUDO" == true ]]; then
        val=$(sudo defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null || echo "NOT_SET")
        if [[ "$val" == "0" ]]; then
            record_check "Privacy Controls" "Location Services" "PASS" "Disabled" "" 2
        elif [[ "$val" == "1" ]]; then
            record_check "Privacy Controls" "Location Services" "WARN" "Enabled — audit app access" "System Settings → Privacy & Security → Location Services" 2
        else
            record_check "Privacy Controls" "Location Services" "SKIP" "Could not check" "" 2
        fi
    else
        record_check "Privacy Controls" "Location Services" "SKIP" "Requires sudo" "" 2
    fi

    local pb=()
    [[ -d "/Applications/DuckDuckGo.app" ]] && pb+=("DuckDuckGo")
    [[ -d "/Applications/Firefox.app" ]] && pb+=("Firefox")
    [[ -d "/Applications/Brave Browser.app" ]] && pb+=("Brave")
    [[ -d "/Applications/LibreWolf.app" ]] && pb+=("LibreWolf")
    [[ -d "/Applications/Tor Browser.app" ]] && pb+=("Tor Browser")
    if [[ ${#pb[@]} -gt 0 ]]; then
        local bl; bl=$(printf ", %s" "${pb[@]}"); bl="${bl:2}"
        record_check "Privacy Controls" "Privacy Browser" "PASS" "Found: ${bl}" "" 2
    else
        record_check "Privacy Controls" "Privacy Browser" "WARN" "None found. Try DuckDuckGo, Firefox+arkenfox, Brave" "https://duckduckgo.com/mac" 2
    fi

    local rb=()
    [[ -d "/Applications/Google Chrome.app" ]] && rb+=("Chrome")
    [[ -d "/Applications/Microsoft Edge.app" ]] && rb+=("Edge")
    [[ -d "/Applications/Opera.app" ]] && rb+=("Opera")
    [[ -d "/Applications/Yandex Browser.app" || -d "/Applications/Yandex.app" ]] && rb+=("Yandex")
    if [[ ${#rb[@]} -gt 0 ]]; then
        local bl; bl=$(printf ", %s" "${rb[@]}"); bl="${bl:2}"
        record_check "Privacy Controls" "High-Telemetry Browsers" "WARN" "Found: ${bl}" "" 1
    else
        record_check "Privacy Controls" "High-Telemetry Browsers" "PASS" "None detected" "" 1
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. ACCESS & AUTH
# ══════════════════════════════════════════════════════════════════════════════
check_access_auth() {
    print_section "4" "ACCESS & AUTHENTICATION"

    local val

    val=$(read_default com.apple.screensaver askForPassword)
    if [[ "$val" == "1" ]]; then
        record_check "Access & Auth" "Password on Wake" "PASS" "Required" "" 4
    else
        record_check "Access & Auth" "Password on Wake" "FAIL" "Not required — physical access = full access" "defaults write com.apple.screensaver askForPassword -int 1" 4
    fi

    val=$(read_default com.apple.screensaver askForPasswordDelay)
    if [[ "$val" == "0" ]]; then
        record_check "Access & Auth" "Password Delay" "PASS" "Immediate (0s)" "" 3
    elif [[ "$val" == "NOT_SET" ]]; then
        record_check "Access & Auth" "Password Delay" "WARN" "Not configured" "defaults write com.apple.screensaver askForPasswordDelay -int 0" 3
    else
        record_check "Access & Auth" "Password Delay" "FAIL" "Delay: ${val}s" "defaults write com.apple.screensaver askForPasswordDelay -int 0" 3
    fi

    val=$(read_default /Library/Preferences/com.apple.loginwindow autoLoginUser)
    if [[ "$val" == "NOT_SET" ]]; then
        record_check "Access & Auth" "Auto-Login" "PASS" "Disabled" "" 4
    else
        record_check "Access & Auth" "Auto-Login" "FAIL" "Enabled for: ${val}" "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser" 4
    fi

    val=$(read_default com.apple.loginwindow RetriesUntilHint)
    if [[ "$val" == "0" || "$val" == "NOT_SET" ]]; then
        record_check "Access & Auth" "Password Hints" "PASS" "Disabled" "" 2
    else
        record_check "Access & Auth" "Password Hints" "WARN" "Shown after ${val} attempts" "sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0" 2
    fi

    val=$(read_default /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)
    if [[ "$val" == "1" ]]; then
        record_check "Access & Auth" "Login Window: Name+Password" "PASS" "User list hidden" "" 2
    else
        record_check "Access & Auth" "Login Window: Name+Password" "WARN" "Shows user list" "sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true" 2
    fi

    local ds; ds=$(pmset -g 2>/dev/null | grep "displaysleep" | awk '{print $2}' || echo "0")
    if [[ "$ds" -le 5 && "$ds" -gt 0 ]]; then
        record_check "Access & Auth" "Display Sleep" "PASS" "Sleeps after ${ds} min" "" 2
    elif [[ "$ds" == "0" ]]; then
        record_check "Access & Auth" "Display Sleep" "WARN" "Never sleeps" "sudo pmset -a displaysleep 2" 2
    else
        record_check "Access & Auth" "Display Sleep" "WARN" "Sleeps after ${ds} min — 2-5 recommended" "sudo pmset -a displaysleep 2" 2
    fi

    if [[ "$HAS_SUDO" == true ]]; then
        local rl; rl=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "")
        if echo "$rl" | grep -qi "off"; then
            record_check "Access & Auth" "Remote Login (SSH)" "PASS" "Disabled" "" 3
        elif echo "$rl" | grep -qi "on"; then
            record_check "Access & Auth" "Remote Login (SSH)" "FAIL" "Enabled" "sudo systemsetup -setremotelogin off" 3
        else
            record_check "Access & Auth" "Remote Login (SSH)" "SKIP" "Could not check" "" 3
        fi
    else
        record_check "Access & Auth" "Remote Login (SSH)" "SKIP" "Requires sudo" "" 3
    fi

    record_check "Access & Auth" "Sudo Timeout" "WARN" "Default 5 min — consider reducing to 1 min" "echo 'Defaults timestamp_timeout=1' | sudo tee /etc/sudoers.d/timeout >/dev/null" 1

    if nvram -x -p 2>/dev/null | grep -q "fmm-mobileme-token-FMM"; then
        record_check "Access & Auth" "Find My Mac" "PASS" "Enabled" "" 3
    else
        record_check "Access & Auth" "Find My Mac" "WARN" "Status unknown — check System Settings → Apple ID → Find My" "" 3
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. APPLICATION SECURITY
# ══════════════════════════════════════════════════════════════════════════════
check_application_security() {
    print_section "5" "APPLICATION SECURITY"

    local dirs=("${HOME}/Library/LaunchAgents:User Launch Agents" "/Library/LaunchAgents:System Launch Agents" "/Library/LaunchDaemons:System Launch Daemons")
    for dp in "${dirs[@]}"; do
        local dir="${dp%%:*}" label="${dp##*:}"
        local suspicious=()
        if [[ -d "$dir" ]]; then
            while IFS= read -r f; do
                [[ -z "$f" ]] && continue
                local b; b=$(basename "$f")
                if ! is_trusted "$b"; then suspicious+=("$b"); fi
            done < <(find "$dir" -name "*.plist" 2>/dev/null)
        fi
        if [[ ${#suspicious[@]} -eq 0 ]]; then
            record_check "Application Security" "$label" "PASS" "No suspicious items" "" 3
        else
            local sl; sl=$(printf ", %s" "${suspicious[@]}"); sl="${sl:2}"
            record_check "Application Security" "$label" "WARN" "Non-standard: ${sl}" "ls -la ${dir}/" 3
        fi
    done

    local li; li=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
    if [[ -n "$li" && "$li" != "" ]]; then
        record_check "Application Security" "Login Items" "WARN" "${li}" "System Settings → General → Login Items" 2
    else
        record_check "Application Security" "Login Items" "PASS" "No user Login Items" "" 2
    fi

    local gk; gk=$(spctl --status 2>/dev/null || echo "")
    if echo "$gk" | grep -q "disabled"; then
        record_check "Application Security" "Gatekeeper Bypass" "FAIL" "Gatekeeper fully disabled" "sudo spctl --master-enable" 4
    else
        record_check "Application Security" "Gatekeeper Bypass" "PASS" "Gatekeeper active" "" 4
    fi

    local ot=()
    [[ -d "/Applications/LuLu.app" ]] && ot+=("LuLu")
    [[ -d "/Applications/BlockBlock Helper.app" || -d "/Applications/BlockBlock.app" ]] && ot+=("BlockBlock")
    [[ -d "/Applications/OverSight.app" ]] && ot+=("OverSight")
    [[ -d "/Applications/KnockKnock.app" ]] && ot+=("KnockKnock")
    [[ -d "/Applications/RansomWhere.app" ]] && ot+=("RansomWhere?")
    if [[ ${#ot[@]} -gt 0 ]]; then
        local tl; tl=$(printf ", %s" "${ot[@]}"); tl="${tl:2}"
        record_check "Application Security" "Security Tools" "PASS" "Installed: ${tl}" "" 2
    else
        record_check "Application Security" "Security Tools" "WARN" "None found. Recommended: LuLu, BlockBlock, KnockKnock, OverSight" "https://objective-see.org/tools.html" 2
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
        if [[ "$mp" -lt 75 ]]; then
            record_check "Performance" "Memory Pressure" "PASS" "${mp}% used (${tmg} GB RAM)" "" 2
        elif [[ "$mp" -lt 90 ]]; then
            record_check "Performance" "Memory Pressure" "WARN" "${mp}% used (${tmg} GB RAM)" "" 2
        else
            record_check "Performance" "Memory Pressure" "FAIL" "${mp}% used (${tmg} GB RAM)" "" 2
        fi
    fi

    local si; si=$(sysctl vm.swapusage 2>/dev/null || echo "")
    local su; su=$(echo "$si" | awk '{for(i=1;i<=NF;i++) if ($i=="used") print $(i+2)}' | sed 's/M//')
    if [[ -n "$su" ]]; then
        local sv; sv=$(echo "$su" | sed 's/\..*//')
        if [[ "${sv:-0}" -lt 1024 ]]; then
            record_check "Performance" "Swap" "PASS" "${su}MB" "" 1
        else
            record_check "Performance" "Swap" "WARN" "${su}MB — high usage" "" 1
        fi
    fi

    local du_out; du_out=$(df -H / 2>/dev/null | tail -1)
    local dp; dp=$(echo "$du_out" | awk '{print $5}' | sed 's/%//')
    local da; da=$(echo "$du_out" | awk '{print $4}')
    if [[ "${dp:-0}" -lt 80 ]]; then
        record_check "Performance" "Disk Space" "PASS" "${dp}% used, ${da} free" "" 2
    elif [[ "${dp:-0}" -lt 95 ]]; then
        record_check "Performance" "Disk Space" "WARN" "${dp}% used, ${da} free" "" 2
    else
        record_check "Performance" "Disk Space" "FAIL" "${dp}% used, ${da} free" "" 2
    fi

    local cs; cs=$(du -sh ~/Library/Caches/ 2>/dev/null | awk '{print $1}' || echo "N/A")
    record_check "Performance" "User Caches" "WARN" "Size: ${cs}" "" 1

    local sn; sn=$(tmutil listlocalsnapshotdates 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    if [[ "${sn:-0}" -gt 10 ]]; then
        record_check "Performance" "TM Snapshots" "WARN" "${sn} local snapshots" "" 1
    else
        record_check "Performance" "TM Snapshots" "PASS" "${sn} snapshots" "" 1
    fi

    local bi; bi=$(pmset -g batt 2>/dev/null || echo "")
    if echo "$bi" | grep -q "InternalBattery"; then
        local bp; bp=$(echo "$bi" | grep -o '[0-9]*%' | head -1 | sed 's/%//')
        local bc; bc=$(system_profiler SPPowerDataType 2>/dev/null | grep "Condition" | awk -F': ' '{print $2}' || echo "Unknown")
        local cc; cc=$(system_profiler SPPowerDataType 2>/dev/null | grep "Cycle Count" | awk -F': ' '{print $2}' || echo "N/A")
        if [[ "$bc" == "Normal" ]]; then
            record_check "Performance" "Battery Health" "PASS" "${bc}, ${bp}%, ${cc} cycles" "" 1
        else
            record_check "Performance" "Battery Health" "WARN" "${bc}, ${bp}%, ${cc} cycles" "" 1
        fi
    fi

    local ut; ut=$(uptime 2>/dev/null | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')
    record_check "Performance" "Uptime" "PASS" "${ut}" "" 0
}

# ══════════════════════════════════════════════════════════════════════════════
# TCC
# ══════════════════════════════════════════════════════════════════════════════
check_tcc_permissions() {
    if [[ "$HAS_SUDO" != true ]]; then return; fi
    print_section "+" "TCC PERMISSIONS AUDIT"
    local tcc="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ ! -f "$tcc" ]]; then return; fi

    local svcs=("kTCCServiceCamera:Camera" "kTCCServiceMicrophone:Microphone" "kTCCServiceScreenCapture:Screen Recording" "kTCCServiceSystemPolicyAllFiles:Full Disk Access" "kTCCServiceAccessibility:Accessibility" "kTCCServiceListenEvent:Input Monitoring")
    for sp in "${svcs[@]}"; do
        local sid="${sp%%:*}" sname="${sp##*:}"
        local apps; apps=$(sudo sqlite3 "$tcc" "SELECT client FROM access WHERE service='${sid}' AND auth_value=2;" 2>/dev/null || echo "")
        if [[ -n "$apps" ]]; then
            local ac; ac=$(echo "$apps" | wc -l | tr -d ' ')
            local al; al=$(echo "$apps" | tr '\n' ', ' | sed 's/,$//')
            record_check "TCC Audit" "TCC: ${sname}" "WARN" "${ac} apps: ${al}" "System Settings → Privacy → ${sname}" 2
        else
            record_check "TCC Audit" "TCC: ${sname}" "PASS" "No apps with access" "" 2
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════
calculate_score() {
    local tw=0 ew=0 i
    for ((i=0; i<${#RESULTS_STATUS[@]}; i++)); do
        local s="${RESULTS_STATUS[$i]}"
        local w="${RESULTS_WEIGHT[$i]}"
        if [[ "$s" == "SKIP" ]]; then continue; fi
        tw=$((tw + w))
        if [[ "$s" == "PASS" ]]; then ew=$((ew + w)); fi
        if [[ "$s" == "WARN" ]]; then ew=$((ew + w / 2)); fi
    done
    if [[ "$tw" -gt 0 ]]; then echo $((ew * 100 / tw)); else echo 0; fi
}

html_escape() {
    echo "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'
}

generate_html_report() {
    local score; score=$(calculate_score)
    local sc="#22c55e" sl="Excellent"
    if [[ "$score" -lt 50 ]]; then sc="#ef4444"; sl="Critical"
    elif [[ "$score" -lt 70 ]]; then sc="#f59e0b"; sl="Needs Attention"
    elif [[ "$score" -lt 85 ]]; then sc="#3b82f6"; sl="Good"; fi

    local circ=452 doff=$((452 - (452 * score / 100)))

    cat > "$REPORT_FILE" << HTMLTOP
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>macOS Security Audit</title>
<style>:root{--bg:#0a0a0b;--bg2:#111113;--bg3:#16161a;--bg4:#1c1c21;--br:#252529;--t1:#e4e4e7;--t2:#a1a1aa;--t3:#71717a;--ac:#a78bfa;--pass:#22c55e;--passbg:rgba(34,197,94,.08);--fail:#ef4444;--failbg:rgba(239,68,68,.08);--warn:#f59e0b;--warnbg:rgba(245,158,11,.08);--skip:#52525b;--skipbg:rgba(82,82,91,.08);--sans:-apple-system,BlinkMacSystemFont,'SF Pro Display',system-ui,sans-serif;--mono:'SF Mono','Fira Code','Consolas',monospace}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--t1);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}.c{max-width:960px;margin:0 auto;padding:40px 24px 80px}.hd{text-align:center;margin-bottom:48px;padding-bottom:32px;border-bottom:1px solid var(--br)}.hd h1{font-size:28px;font-weight:600;letter-spacing:-.5px;margin-bottom:16px}.mg{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 24px;font-size:13px;color:var(--t2);font-family:var(--mono)}.mg span{opacity:.6}.mg strong{color:var(--t1);font-weight:500}.ss{display:flex;flex-direction:column;align-items:center;margin:40px 0}.sr{position:relative;width:160px;height:160px}.sr svg{transform:rotate(-90deg);width:160px;height:160px}.sr circle{fill:none;stroke-width:8;stroke-linecap:round}.sbg{stroke:var(--br)}.sv{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}.sn{font-size:42px;font-weight:700;letter-spacing:-2px;line-height:1}.sla{font-size:12px;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-top:4px}.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:32px 0 48px}.scard{background:var(--bg3);border:1px solid var(--br);border-radius:10px;padding:16px;text-align:center}.scard .ct{font-size:28px;font-weight:700}.scard .lb{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--t3);margin-top:4px}.sec{margin-bottom:32px}.sh{display:flex;align-items:center;gap:12px;padding:12px 0;margin-bottom:8px;border-bottom:1px solid var(--br)}.sh h2{font-size:16px;font-weight:600}.snm{background:var(--bg4);color:var(--t3);font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;font-family:var(--mono)}.ci{display:grid;grid-template-columns:72px 1fr;padding:12px 0;border-bottom:1px solid var(--bg4);align-items:start}.ci:last-child{border-bottom:none}.sb{font-size:11px;font-weight:600;font-family:var(--mono);text-transform:uppercase;padding:3px 8px;border-radius:4px;width:fit-content}.sp{color:var(--pass);background:var(--passbg)}.sf{color:var(--fail);background:var(--failbg)}.sw{color:var(--warn);background:var(--warnbg)}.sk{color:var(--skip);background:var(--skipbg)}.cb h3{font-size:14px;font-weight:500;margin-bottom:4px}.cd{font-size:13px;color:var(--t2)}.cf{margin-top:6px;padding:6px 10px;background:var(--bg2);border:1px solid var(--br);border-radius:6px;font-family:var(--mono);font-size:12px;color:var(--ac);word-break:break-all;cursor:pointer}.cf:hover{border-color:var(--ac)}.qf{margin-top:48px;padding:24px;background:var(--bg3);border:1px solid var(--br);border-radius:12px}.qf h2{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--fail)}.qb{background:var(--bg);border:1px solid var(--br);border-radius:8px;padding:16px;font-family:var(--mono);font-size:12px;line-height:1.8;white-space:pre-wrap;word-break:break-all;cursor:pointer;position:relative}.qb:hover{border-color:var(--ac)}.mr{margin-top:32px;padding:24px;background:var(--bg3);border:1px solid var(--br);border-radius:12px}.mr h2{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--ac)}.mr ul{list-style:none}.mr li{padding:8px 0;border-bottom:1px solid var(--bg4);font-size:13px;color:var(--t2)}.mr li:last-child{border-bottom:none}.mr li strong{color:var(--t1)}.ft{text-align:center;margin-top:48px;padding-top:24px;border-top:1px solid var(--br);font-size:12px;color:var(--t3)}@media(max-width:640px){.sg{grid-template-columns:repeat(2,1fr)}.ci{grid-template-columns:64px 1fr}.mg{grid-template-columns:1fr}}</style></head><body><div class="c">
<div class="hd"><h1>macOS Security Audit</h1><div class="mg"><div><span>Host:</span> <strong>${HOSTNAME_VAL}</strong></div><div><span>macOS:</span> <strong>${MACOS_VERSION} (${MACOS_BUILD})</strong></div><div><span>Model:</span> <strong>${HARDWARE_MODEL}</strong></div><div><span>Chip:</span> <strong>${CHIP}</strong></div><div><span>Arch:</span> <strong>${ARCH}</strong></div><div><span>Date:</span> <strong>${AUDIT_DATE}</strong></div><div><span>Serial:</span> <strong>${SERIAL}</strong></div><div><span>Script:</span> <strong>v${SCRIPT_VERSION}</strong></div></div></div>
<div class="ss"><div class="sr"><svg viewBox="0 0 160 160"><circle class="sbg" cx="80" cy="80" r="72"/><circle cx="80" cy="80" r="72" stroke="${sc}" stroke-dasharray="${circ}" stroke-dashoffset="${doff}"/></svg><div class="sv"><div class="sn" style="color:${sc}">${score}</div><div class="sla">${sl}</div></div></div></div>
<div class="sg"><div class="scard"><div class="ct" style="color:var(--pass)">${PASS_COUNT}</div><div class="lb">Pass</div></div><div class="scard"><div class="ct" style="color:var(--fail)">${FAIL_COUNT}</div><div class="lb">Fail</div></div><div class="scard"><div class="ct" style="color:var(--warn)">${WARN_COUNT}</div><div class="lb">Warn</div></div><div class="scard"><div class="ct" style="color:var(--skip)">${SKIP_COUNT}</div><div class="lb">Skip</div></div></div>
HTMLTOP

    local cc="" snum=0 i
    for ((i=0; i<${#RESULTS_STATUS[@]}; i++)); do
        local ct="${RESULTS_CATEGORY[$i]}"
        local nm; nm=$(html_escape "${RESULTS_NAME[$i]}")
        local st="${RESULTS_STATUS[$i]}"
        local dt; dt=$(html_escape "${RESULTS_DETAIL[$i]}")
        local fx; fx=$(html_escape "${RESULTS_FIX[$i]}")

        if [[ "$ct" != "$cc" ]]; then
            if [[ -n "$cc" ]]; then echo "</div>" >> "$REPORT_FILE"; fi
            cc="$ct"; snum=$((snum+1))
            echo "<div class=\"sec\"><div class=\"sh\"><span class=\"snm\">${snum}</span><h2>${ct}</h2></div>" >> "$REPORT_FILE"
        fi
        local scl="sp"
        case "$st" in FAIL) scl="sf" ;; WARN) scl="sw" ;; SKIP) scl="sk" ;; esac

        echo "<div class=\"ci\"><div><span class=\"sb ${scl}\">${st}</span></div><div class=\"cb\"><h3>${nm}</h3><div class=\"cd\">${dt}</div>" >> "$REPORT_FILE"
        if [[ -n "$fx" ]]; then
            echo "<div class=\"cf\" onclick=\"navigator.clipboard.writeText(this.textContent.trim())\">${fx}</div>" >> "$REPORT_FILE"
        fi
        echo "</div></div>" >> "$REPORT_FILE"
    done
    if [[ -n "$cc" ]]; then echo "</div>" >> "$REPORT_FILE"; fi

    if [[ ${#QUICK_FIXES[@]} -gt 0 ]]; then
        echo '<div class="qf"><h2>⚡ Quick Fix</h2><div class="qb" onclick="navigator.clipboard.writeText(this.innerText.trim())">' >> "$REPORT_FILE"
        for q in "${QUICK_FIXES[@]}"; do
            echo "${q%%|*}" >> "$REPORT_FILE"
            echo "${q##*|}" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        done
        echo '</div></div>' >> "$REPORT_FILE"
    fi

    cat >> "$REPORT_FILE" << 'HTMLBOT'
<div class="mr"><h2>📋 Manual Recommendations</h2><ul>
<li><strong>VPN:</strong> Use a no-log VPN (Mullvad, ProtonVPN, IVPN). Enable kill switch, WireGuard, DNS leak protection.</li>
<li><strong>Browser:</strong> DuckDuckGo, Firefox+arkenfox, Brave, LibreWolf. Disable WebRTC: about:config → media.peerconnection.enabled=false</li>
<li><strong>Crypto/Banking:</strong> Dedicated browser profile — never mix with everyday browsing.</li>
<li><strong>Passwords:</strong> Bitwarden or 1Password. Master: 4+ diceware words. Enable TOTP/FIDO2.</li>
<li><strong>MFA:</strong> Critical accounts → YubiKey. Others → TOTP (Ente Auth). No SMS MFA.</li>
<li><strong>Apple ID:</strong> Enable Advanced Data Protection. Bind YubiKey.</li>
<li><strong>Messaging:</strong> Signal — disappearing messages, Registration Lock, Screen Lock.</li>
<li><strong>Tools:</strong> LuLu, BlockBlock, KnockKnock, OverSight — free at objective-see.org</li>
<li><strong>Backup:</strong> Encrypted Time Machine. Test restore quarterly.</li>
<li><strong>Leak Tests:</strong> dnsleaktest.com (extended), browserleaks.com/webrtc</li>
</ul></div>
HTMLBOT

    echo "<div class=\"ft\">macOS Security Audit v${SCRIPT_VERSION} · ${AUDIT_DATE} · ${HOSTNAME_VAL}</div></div>" >> "$REPORT_FILE"
    echo '<script>document.querySelectorAll(".cf").forEach(e=>e.addEventListener("click",function(){navigator.clipboard.writeText(this.textContent.trim()).then(()=>{this.style.borderColor="var(--pass)";setTimeout(()=>this.style.borderColor="",800)})}))</script></body></html>' >> "$REPORT_FILE"
}

# ══════════════════════════════════════════════════════════════════════════════
main() {
    clear
    print_banner
    HAS_SUDO=false
    request_sudo
    echo ""
    echo -e "${BOLD}Running audit...${NC}"
    check_system_integrity
    check_network_security
    check_privacy_controls
    check_access_auth
    check_application_security
    check_performance_health
    check_tcc_permissions
    echo ""
    echo -e "${BOLD}${CYAN}Generating HTML report...${NC}"
    generate_html_report
    local score; score=$(calculate_score)
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  AUDIT RESULTS${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "  Security Score: ${BOLD}${score}/100${NC}"
    echo -e "  ${GREEN}PASS: ${PASS_COUNT}${NC}  ${RED}FAIL: ${FAIL_COUNT}${NC}  ${YELLOW}WARN: ${WARN_COUNT}${NC}  ${DIM}SKIP: ${SKIP_COUNT}${NC}"
    echo -e "  Total checks: ${TOTAL_CHECKS}"
    echo -e "  HTML report: ${BOLD}${REPORT_FILE}${NC}"
    echo ""
    open "$REPORT_FILE" 2>/dev/null || true
    if [[ -n "${SUDO_KEEPER_PID:-}" ]]; then
        kill "$SUDO_KEEPER_PID" 2>/dev/null || true
    fi
}
main "$@"
