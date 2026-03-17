#!/bin/bash
set -uo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  macOS Security Audit Tool v1.0                                             ║
# ║  Полный аудит безопасности macOS с генерацией HTML-отчёта                    ║
# ║  Совместимость: macOS 12+ (Monterey), Intel & Apple Silicon                 ║
# ║  Mullvad VPN-aware | LuLu-aware | DuckDuckGo-aware                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Конфигурация ──
SCRIPT_VERSION="1.0.0"
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

# ── Цвета для терминала ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Счётчики ──
TOTAL_CHECKS=0
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

# ── Массивы для результатов ──
declare -a RESULTS_JSON=()
declare -a QUICK_FIXES=()
declare -a MANUAL_RECS=()

# ── Whitelist доверенных процессов/агентов ──
TRUSTED_PATTERNS=(
    "com.apple."
    "com.mullvad"
    "com.objective-see.lulu"
    "com.duckduckgo"
)

# ── Известные Mullvad DNS ──
MULLVAD_DNS_PATTERNS=(
    "10.64.0.1"
    "100.64.0"
    "10.124.0"
)

# ══════════════════════════════════════════════════════════════════════════════
# ФУНКЦИИ ЯДРА
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
    local section_num="$1"
    local section_name="$2"
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  ${section_num}. ${section_name}${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Функция записи результата проверки
# Аргументы: категория, название, статус (PASS/FAIL/WARN/SKIP), описание, fix-команда, вес
record_check() {
    local category="$1"
    local name="$2"
    local status="$3"
    local detail="$4"
    local fix="${5:-}"
    local weight="${6:-1}"
    local priority="${7:-recommended}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1))
              echo -e "  ${GREEN}✓ PASS${NC}  ${name}"
              ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1))
              echo -e "  ${RED}✗ FAIL${NC}  ${name}"
              if [[ -n "$fix" ]]; then
                  echo -e "         ${DIM}Fix: ${fix}${NC}"
              fi
              ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1))
              echo -e "  ${YELLOW}⚠ WARN${NC}  ${name}"
              ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1))
              echo -e "  ${DIM}○ SKIP${NC}  ${name} ${DIM}(${detail})${NC}"
              ;;
    esac

    # Экранирование для JSON/HTML
    local safe_detail
    safe_detail=$(echo "$detail" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g; s/&/\&amp;/g')
    local safe_fix
    safe_fix=$(echo "$fix" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g; s/&/\&amp;/g')
    local safe_name
    safe_name=$(echo "$name" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g')

    RESULTS_JSON+=("{\"category\":\"${category}\",\"name\":\"${safe_name}\",\"status\":\"${status}\",\"detail\":\"${safe_detail}\",\"fix\":\"${safe_fix}\",\"weight\":${weight},\"priority\":\"${priority}\"}")

    if [[ "$status" == "FAIL" && -n "$fix" ]]; then
        QUICK_FIXES+=("# ${name}|${fix}")
    fi
}

# Проверка: входит ли строка в доверенный whitelist
is_trusted() {
    local item="$1"
    for pattern in "${TRUSTED_PATTERNS[@]}"; do
        if [[ "$item" == *"$pattern"* ]]; then
            return 0
        fi
    done
    return 1
}

# Получить sudo один раз
request_sudo() {
    echo -e "${YELLOW}Некоторые проверки требуют sudo (Firewall, TCC, системные настройки).${NC}"
    echo -e "${DIM}Пароль запрашивается один раз и кэшируется на время аудита.${NC}"
    echo ""
    sudo -v 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo -e "${YELLOW}⚠ sudo недоступен. Часть проверок будет пропущена.${NC}"
        HAS_SUDO=false
    else
        HAS_SUDO=true
        # Поддерживать sudo-сессию активной в фоне
        while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
        SUDO_KEEPER_PID=$!
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. SYSTEM INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════

check_system_integrity() {
    print_section "1" "SYSTEM INTEGRITY"

    # ── 1.1 SIP (System Integrity Protection) ──
    # Что: защита системных файлов от модификации
    # Зачем: SIP предотвращает rootkit, модификацию системных бинарников
    # Ожидание: enabled
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "Unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        record_check "System Integrity" "SIP (System Integrity Protection)" "PASS" "SIP включён" "" 5 "critical"
    else
        record_check "System Integrity" "SIP (System Integrity Protection)" "FAIL" "SIP выключен — система уязвима к rootkit и модификации системных файлов" "Перезагрузка в Recovery Mode → Terminal → csrutil enable" 5 "critical"
    fi

    # ── 1.2 FileVault ──
    # Что: полнодисковое шифрование
    # Зачем: защита данных при физическом доступе к диску
    # Ожидание: On
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "Unknown")
    if echo "$fv_status" | grep -q "FileVault is On"; then
        record_check "System Integrity" "FileVault 2 (шифрование диска)" "PASS" "FileVault включён" "" 5 "critical"
    elif echo "$fv_status" | grep -q "Encryption in progress"; then
        record_check "System Integrity" "FileVault 2 (шифрование диска)" "WARN" "FileVault: шифрование в процессе" "" 5 "critical"
    else
        record_check "System Integrity" "FileVault 2 (шифрование диска)" "FAIL" "Диск не зашифрован — данные доступны при физическом доступе" "sudo fdesetup enable" 5 "critical"
    fi

    # ── 1.3 Gatekeeper ──
    # Что: проверка подписи приложений
    # Зачем: блокирует запуск неподписанного/вредоносного софта
    # Ожидание: assessments enabled
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "Unknown")
    if echo "$gk_status" | grep -q "assessments enabled"; then
        record_check "System Integrity" "Gatekeeper" "PASS" "Gatekeeper активен" "" 4 "critical"
    else
        record_check "System Integrity" "Gatekeeper" "FAIL" "Gatekeeper отключён — возможен запуск неподписанного софта" "sudo spctl --master-enable" 4 "critical"
    fi

    # ── 1.4 XProtect / MRT обновления ──
    # Что: автоматические обновления баз вредоносного ПО
    # Зачем: без обновлений — нулевая защита от известных угроз
    # Ожидание: AutomaticallyInstallMacOSUpdates = 1
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" == "1" ]]; then
        record_check "System Integrity" "Автоматические обновления macOS" "PASS" "Автообновления macOS включены" "" 3 "important"
    else
        record_check "System Integrity" "Автоматические обновления macOS" "FAIL" "Автообновления macOS отключены" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true" 3 "important"
    fi

    # ── 1.5 Rapid Security Responses ──
    local critical_update
    critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$critical_update" == "1" ]]; then
        record_check "System Integrity" "Rapid Security Responses" "PASS" "Быстрые обновления безопасности включены" "" 4 "critical"
    else
        record_check "System Integrity" "Rapid Security Responses" "FAIL" "Rapid Security Responses отключены — критические патчи не ставятся автоматически" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true" 4 "critical"
    fi

    # ── 1.6 Автоматическая проверка обновлений ──
    local auto_check
    auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "not set")
    if [[ "$auto_check" == "1" ]]; then
        record_check "System Integrity" "Автоматическая проверка обновлений" "PASS" "Автопроверка обновлений включена" "" 2 "important"
    else
        record_check "System Integrity" "Автоматическая проверка обновлений" "FAIL" "Автопроверка обновлений отключена" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true" 2 "important"
    fi

    # ── 1.7 Автозагрузка обновлений ──
    local auto_download
    auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "not set")
    if [[ "$auto_download" == "1" ]]; then
        record_check "System Integrity" "Автозагрузка обновлений" "PASS" "Автоскачивание обновлений включено" "" 2 "important"
    else
        record_check "System Integrity" "Автозагрузка обновлений" "FAIL" "Автоскачивание обновлений отключено" "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true" 2 "important"
    fi

    # ── 1.8 Установка обновлений приложений ──
    local app_update
    app_update=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "not set")
    if [[ "$app_update" == "1" ]]; then
        record_check "System Integrity" "Автообновление приложений App Store" "PASS" "Автообновление приложений включено" "" 1 "recommended"
    else
        record_check "System Integrity" "Автообновление приложений App Store" "WARN" "Автообновление приложений App Store не включено" "sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true" 1 "recommended"
    fi

    # ── 1.9 EFI Integrity (только Intel) ──
    if [[ "$ARCH" == "x86_64" ]]; then
        if [[ -f "/usr/libexec/firmwarecheckers/eficheck/eficheck" ]]; then
            local efi_result
            efi_result=$(/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check 2>&1 || true)
            if echo "$efi_result" | grep -qi "passed\|No changes"; then
                record_check "System Integrity" "EFI Firmware Integrity" "PASS" "EFI firmware прошёл проверку целостности" "" 5 "critical"
            elif echo "$efi_result" | grep -qi "not supported\|error"; then
                record_check "System Integrity" "EFI Firmware Integrity" "SKIP" "Проверка EFI не поддерживается на этом Mac" "" 0 "info"
            else
                record_check "System Integrity" "EFI Firmware Integrity" "WARN" "EFI firmware: результат неоднозначен — рекомендуется ручная проверка" "" 5 "critical"
            fi
        fi
    else
        record_check "System Integrity" "Secure Boot (Apple Silicon)" "PASS" "Apple Silicon использует Secure Boot по умолчанию (Full Security)" "" 5 "critical"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. NETWORK SECURITY
# ══════════════════════════════════════════════════════════════════════════════

check_network_security() {
    print_section "2" "NETWORK SECURITY"

    # ── 2.1 Application Firewall ──
    # Что: встроенный firewall macOS
    # Зачем: блокирует нежелательные входящие подключения
    # Ожидание: enabled
    local fw_state=""
    if [[ "$HAS_SUDO" == true ]]; then
        fw_state=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "")
    fi
    if echo "$fw_state" | grep -q "enabled"; then
        record_check "Network Security" "Application Firewall" "PASS" "Firewall включён" "" 4 "critical"
    elif [[ -z "$fw_state" ]]; then
        record_check "Network Security" "Application Firewall" "SKIP" "Требуется sudo для проверки" "" 4 "critical"
    else
        record_check "Network Security" "Application Firewall" "FAIL" "Firewall выключен — входящие подключения не фильтруются" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" 4 "critical"
    fi

    # ── 2.2 Stealth Mode ──
    # Что: невидимость для сетевых сканеров
    # Зачем: Mac не отвечает на ICMP ping и port scan
    local stealth=""
    if [[ "$HAS_SUDO" == true ]]; then
        stealth=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "")
    fi
    if echo "$stealth" | grep -q "enabled"; then
        record_check "Network Security" "Firewall Stealth Mode" "PASS" "Stealth Mode включён — Mac невидим для сканеров" "" 3 "important"
    elif [[ -z "$stealth" ]]; then
        record_check "Network Security" "Firewall Stealth Mode" "SKIP" "Требуется sudo" "" 3 "important"
    else
        record_check "Network Security" "Firewall Stealth Mode" "FAIL" "Stealth Mode выключен — Mac отвечает на ping/port scan" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on" 3 "important"
    fi

    # ── 2.3 Block All Incoming ──
    local block_all=""
    if [[ "$HAS_SUDO" == true ]]; then
        block_all=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo "")
    fi
    if echo "$block_all" | grep -q "enabled"; then
        record_check "Network Security" "Block All Incoming Connections" "PASS" "Блокировка всех входящих включена" "" 2 "important"
    elif [[ -z "$block_all" ]]; then
        record_check "Network Security" "Block All Incoming Connections" "SKIP" "Требуется sudo" "" 2 "important"
    else
        record_check "Network Security" "Block All Incoming Connections" "WARN" "Block All Incoming выключен — исключения для сервисов разрешены. Рекомендуется включить если нет необходимости в входящих." "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on" 2 "important"
    fi

    # ── 2.4 Mullvad VPN — туннель активен ──
    # Что: проверка наличия VPN-туннеля
    # Зачем: без туннеля — весь трафик идёт в открытом виде
    local vpn_tunnel
    vpn_tunnel=$(ifconfig 2>/dev/null | grep -c "utun" || echo "0")
    local mullvad_proc
    mullvad_proc=$(pgrep -f "mullvad" 2>/dev/null | head -1 || echo "")
    if [[ "$vpn_tunnel" -gt 0 && -n "$mullvad_proc" ]]; then
        record_check "Network Security" "Mullvad VPN — туннель" "PASS" "VPN-туннель активен (utun интерфейс обнаружен, процесс Mullvad запущен)" "" 5 "critical"
    elif [[ "$vpn_tunnel" -gt 0 ]]; then
        record_check "Network Security" "Mullvad VPN — туннель" "WARN" "utun-интерфейс найден, но процесс Mullvad не обнаружен — возможно другой VPN" "" 5 "critical"
    else
        record_check "Network Security" "Mullvad VPN — туннель" "FAIL" "VPN-туннель не обнаружен — трафик не защищён" "Запустите Mullvad VPN" 5 "critical"
    fi

    # ── 2.5 Mullvad VPN — DNS Leak Check ──
    # Что: проверка что DNS-запросы идут через VPN
    # Зачем: утечка DNS = ISP видит все посещаемые домены
    local dns_servers
    dns_servers=$(scutil --dns 2>/dev/null | grep "nameserver\[" | awk '{print $3}' | sort -u)
    local dns_leak=false
    local mullvad_dns_found=false

    if [[ -n "$dns_servers" ]]; then
        while IFS= read -r dns; do
            local is_mullvad=false
            for pattern in "${MULLVAD_DNS_PATTERNS[@]}"; do
                if [[ "$dns" == ${pattern}* ]]; then
                    is_mullvad=true
                    mullvad_dns_found=true
                    break
                fi
            done
            # Localhost и link-local — допустимы
            if [[ "$dns" == "127."* || "$dns" == "::1" || "$dns" == "fe80:"* ]]; then
                continue
            fi
            if [[ "$is_mullvad" == false ]]; then
                dns_leak=true
            fi
        done <<< "$dns_servers"
    fi

    if [[ "$mullvad_dns_found" == true && "$dns_leak" == false ]]; then
        record_check "Network Security" "DNS Leak Check (Mullvad)" "PASS" "Все DNS-запросы идут через Mullvad DNS" "" 5 "critical"
    elif [[ "$mullvad_dns_found" == true && "$dns_leak" == true ]]; then
        record_check "Network Security" "DNS Leak Check (Mullvad)" "WARN" "Mullvad DNS обнаружен, но присутствуют и не-VPN DNS серверы — возможна утечка" "В Mullvad → Settings → Use Mullvad DNS; также: networksetup -setdnsservers Wi-Fi 10.64.0.1" 5 "critical"
    else
        record_check "Network Security" "DNS Leak Check (Mullvad)" "FAIL" "Mullvad DNS не обнаружен — DNS-запросы идут мимо VPN" "Проверьте настройки Mullvad → DNS; networksetup -setdnsservers Wi-Fi 10.64.0.1" 5 "critical"
    fi

    # ── 2.6 Маршрут по умолчанию через VPN ──
    local default_route
    default_route=$(route -n get default 2>/dev/null | grep "interface:" | awk '{print $2}' || echo "")
    if [[ "$default_route" == utun* ]]; then
        record_check "Network Security" "Default Route через VPN" "PASS" "Маршрут по умолчанию идёт через VPN-туннель (${default_route})" "" 4 "critical"
    elif [[ -n "$default_route" ]]; then
        record_check "Network Security" "Default Route через VPN" "WARN" "Маршрут по умолчанию: ${default_route} — не через VPN-туннель. Mullvad может использовать split tunneling." "" 4 "critical"
    fi

    # ── 2.7 LuLu (Outbound Firewall) ──
    # Что: контроль исходящих подключений
    # Зачем: macOS не имеет встроенного outbound firewall — LuLu закрывает этот пробел
    local lulu_app=false
    local lulu_running=false
    if [[ -d "/Applications/LuLu.app" ]]; then
        lulu_app=true
    fi
    if pgrep -x "LuLu" >/dev/null 2>&1; then
        lulu_running=true
    fi

    if [[ "$lulu_app" == true && "$lulu_running" == true ]]; then
        record_check "Network Security" "LuLu (Outbound Firewall)" "PASS" "LuLu установлен и запущен — исходящие подключения контролируются" "" 3 "important"
    elif [[ "$lulu_app" == true && "$lulu_running" == false ]]; then
        record_check "Network Security" "LuLu (Outbound Firewall)" "WARN" "LuLu установлен, но не запущен" "Запустите LuLu из /Applications" 3 "important"
    else
        record_check "Network Security" "LuLu (Outbound Firewall)" "FAIL" "LuLu не установлен — нет контроля исходящих подключений. macOS не имеет встроенного outbound firewall." "Скачать: https://objective-see.org/products/lulu.html" 3 "important"
    fi

    # ── 2.8 Sharing Services ──
    # Что: сетевые сервисы общего доступа
    # Зачем: каждый открытый сервис — потенциальная точка входа
    local sharing_services=("Remote Login:ssh" "Screen Sharing:screensharing" "File Sharing:smb" "Remote Management:remotemanagement" "Printer Sharing:printersharing" "Content Caching:contentcaching" "Remote Apple Events:remoteappleevents")

    for service_pair in "${sharing_services[@]}"; do
        local display_name="${service_pair%%:*}"
        local service_name="${service_pair##*:}"
        local is_on=false

        case "$service_name" in
            ssh)
                local ssh_status
                ssh_status=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "")
                if echo "$ssh_status" | grep -qi "on"; then
                    is_on=true
                fi
                ;;
            *)
                # Проверяем через launchctl
                if launchctl list 2>/dev/null | grep -qi "$service_name"; then
                    is_on=true
                fi
                ;;
        esac

        if [[ "$is_on" == true ]]; then
            local fix_cmd=""
            if [[ "$service_name" == "ssh" ]]; then
                fix_cmd="sudo systemsetup -setremotelogin off"
            else
                fix_cmd="System Settings → General → Sharing → отключить ${display_name}"
            fi
            record_check "Network Security" "Sharing: ${display_name}" "FAIL" "${display_name} включён — потенциальная точка входа" "$fix_cmd" 3 "important"
        else
            record_check "Network Security" "Sharing: ${display_name}" "PASS" "${display_name} отключён" "" 3 "important"
        fi
    done

    # ── 2.9 AirDrop ──
    local airdrop
    airdrop=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null || echo "not set")
    if [[ "$airdrop" == "Off" ]]; then
        record_check "Network Security" "AirDrop" "PASS" "AirDrop отключён" "" 2 "recommended"
    elif [[ "$airdrop" == "Contacts Only" ]]; then
        record_check "Network Security" "AirDrop" "PASS" "AirDrop: только для контактов" "" 2 "recommended"
    else
        record_check "Network Security" "AirDrop" "WARN" "AirDrop доступен для всех — рекомендуется Contacts Only или Off" "defaults write com.apple.sharingd DiscoverableMode -string 'Contacts Only'" 2 "recommended"
    fi

    # ── 2.10 Bluetooth ──
    local bt_power
    bt_power=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "1")
    if [[ "$bt_power" == "0" ]]; then
        record_check "Network Security" "Bluetooth" "PASS" "Bluetooth выключен — минимальная attack surface" "" 1 "recommended"
    else
        record_check "Network Security" "Bluetooth" "WARN" "Bluetooth включён — увеличивает attack surface (KNOB, BIAS). Выключайте когда не используется." "" 1 "recommended"
    fi

    # ── 2.11 Wi-Fi — автоподключение к сетям ──
    local wifi_autojoin_warn=false
    local known_networks
    known_networks=$(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2 | sed 's/^[[:space:]]*//' || echo "")
    local network_count
    network_count=$(echo "$known_networks" | grep -c "." 2>/dev/null || echo "0")

    if [[ "$network_count" -gt 10 ]]; then
        record_check "Network Security" "Wi-Fi: запомненные сети" "WARN" "Запомнено ${network_count} Wi-Fi сетей — рекомендуется удалить неиспользуемые (risk: auto-connect к evil twin)" "networksetup -removepreferredwirelessnetwork en0 'ИМЯ_СЕТИ'" 2 "recommended"
    else
        record_check "Network Security" "Wi-Fi: запомненные сети" "PASS" "Запомнено ${network_count} Wi-Fi сетей" "" 2 "recommended"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. PRIVACY CONTROLS
# ══════════════════════════════════════════════════════════════════════════════

check_privacy_controls() {
    print_section "3" "PRIVACY CONTROLS"

    # ── 3.1 Apple Analytics ──
    local analytics
    analytics=$(defaults read /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null || echo "not set")
    if [[ "$analytics" == "0" ]]; then
        record_check "Privacy Controls" "Apple Analytics (Diagnostics)" "PASS" "Отправка диагностики отключена" "" 2 "important"
    else
        record_check "Privacy Controls" "Apple Analytics (Diagnostics)" "FAIL" "Отправка диагностики включена — Apple получает данные о вашем использовании" "sudo defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool false" 2 "important"
    fi

    # ── 3.2 Crash Reporter ──
    local crash_diag
    crash_diag=$(defaults read com.apple.CrashReporter DialogType 2>/dev/null || echo "not set")
    if [[ "$crash_diag" == "none" ]]; then
        record_check "Privacy Controls" "Crash Reporter" "PASS" "Crash Reporter не отправляет данные" "" 1 "recommended"
    else
        record_check "Privacy Controls" "Crash Reporter" "WARN" "Crash Reporter может отправлять данные о сбоях" "defaults write com.apple.CrashReporter DialogType -string 'none'" 1 "recommended"
    fi

    # ── 3.3 Personalized Ads ──
    local ads
    ads=$(defaults read com.apple.AdLib forceLimitAdTracking 2>/dev/null || echo "not set")
    if [[ "$ads" == "1" ]]; then
        record_check "Privacy Controls" "Персонализированная реклама Apple" "PASS" "Персонализированная реклама ограничена" "" 2 "important"
    else
        record_check "Privacy Controls" "Персонализированная реклама Apple" "FAIL" "Персонализированная реклама не ограничена" "defaults write com.apple.AdLib forceLimitAdTracking -bool true" 2 "important"
    fi

    # ── 3.4 Siri ──
    local siri_enabled
    siri_enabled=$(defaults read com.apple.assistant.support "Assistant Enabled" 2>/dev/null || echo "not set")
    if [[ "$siri_enabled" == "0" ]]; then
        record_check "Privacy Controls" "Siri" "PASS" "Siri отключён" "" 2 "important"
    else
        record_check "Privacy Controls" "Siri" "WARN" "Siri включён — голосовые запросы могут обрабатываться на серверах Apple" "defaults write com.apple.assistant.support 'Assistant Enabled' -bool false" 2 "important"
    fi

    # ── 3.5 Siri Data Sharing ──
    local siri_sharing
    siri_sharing=$(defaults read com.apple.assistant.support "Siri Data Sharing Opt-In Status" 2>/dev/null || echo "not set")
    if [[ "$siri_sharing" == "2" || "$siri_sharing" == "0" ]]; then
        record_check "Privacy Controls" "Siri Data Sharing" "PASS" "Передача данных Siri отключена" "" 2 "important"
    elif [[ "$siri_sharing" == "not set" ]]; then
        record_check "Privacy Controls" "Siri Data Sharing" "WARN" "Статус передачи данных Siri не определён" "" 2 "important"
    else
        record_check "Privacy Controls" "Siri Data Sharing" "FAIL" "Передача данных Siri включена" "defaults write com.apple.assistant.support 'Siri Data Sharing Opt-In Status' -int 2" 2 "important"
    fi

    # ── 3.6 Spotlight Suggestions (утечка поисковых запросов) ──
    local spotlight_sug
    spotlight_sug=$(defaults read com.apple.lookup.shared LookupSuggestionsDisabled 2>/dev/null || echo "not set")
    if [[ "$spotlight_sug" == "1" ]]; then
        record_check "Privacy Controls" "Spotlight Suggestions (сетевые)" "PASS" "Сетевые Spotlight Suggestions отключены" "" 2 "important"
    else
        record_check "Privacy Controls" "Spotlight Suggestions (сетевые)" "FAIL" "Spotlight Suggestions отправляют поисковые запросы Apple" "defaults write com.apple.lookup.shared LookupSuggestionsDisabled -bool true" 2 "important"
    fi

    # ── 3.7 Safari Suggestions ──
    local safari_sug
    safari_sug=$(defaults read com.apple.Safari UniversalSearchEnabled 2>/dev/null || echo "not set")
    if [[ "$safari_sug" == "0" ]]; then
        record_check "Privacy Controls" "Safari Suggestions" "PASS" "Safari Suggestions отключены" "" 1 "recommended"
    else
        record_check "Privacy Controls" "Safari Suggestions" "WARN" "Safari Suggestions включены — запросы отправляются Apple" "defaults write com.apple.Safari UniversalSearchEnabled -bool false" 1 "recommended"
    fi

    # ── 3.8 Location Services ──
    local location
    if [[ "$HAS_SUDO" == true ]]; then
        location=$(sudo defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null || echo "not set")
    else
        location="not set"
    fi
    if [[ "$location" == "0" ]]; then
        record_check "Privacy Controls" "Location Services" "PASS" "Службы геолокации отключены" "" 2 "important"
    elif [[ "$location" == "1" ]]; then
        record_check "Privacy Controls" "Location Services" "WARN" "Службы геолокации включены — проверьте список приложений с доступом" "System Settings → Privacy & Security → Location Services → аудит" 2 "important"
    else
        record_check "Privacy Controls" "Location Services" "SKIP" "Не удалось проверить (требуется sudo)" "" 2 "important"
    fi

    # ── 3.9 DuckDuckGo Browser ──
    # Что: проверка наличия privacy-first браузера
    # Зачем: DuckDuckGo Browser имеет встроенную защиту от трекеров, fire button, принудительный HTTPS
    if [[ -d "/Applications/DuckDuckGo.app" ]]; then
        record_check "Privacy Controls" "DuckDuckGo Browser" "PASS" "DuckDuckGo Browser установлен — встроенная защита от трекеров, fingerprinting, HTTPS upgrade" "" 2 "recommended"
    else
        record_check "Privacy Controls" "DuckDuckGo Browser" "WARN" "DuckDuckGo Browser не установлен — рекомендуется как privacy-first браузер" "Скачать: https://duckduckgo.com/mac" 2 "recommended"
    fi

    # ── 3.10 Проверка других браузеров (potential privacy risk) ──
    local risky_browsers=()
    [[ -d "/Applications/Google Chrome.app" ]] && risky_browsers+=("Google Chrome")
    [[ -d "/Applications/Microsoft Edge.app" ]] && risky_browsers+=("Microsoft Edge")
    [[ -d "/Applications/Opera.app" ]] && risky_browsers+=("Opera")

    if [[ ${#risky_browsers[@]} -gt 0 ]]; then
        local browser_list
        browser_list=$(printf ", %s" "${risky_browsers[@]}")
        browser_list="${browser_list:2}"
        record_check "Privacy Controls" "Браузеры с телеметрией" "WARN" "Установлены браузеры с повышенной телеметрией: ${browser_list}. Не используйте для чувствительных операций без hardening." "" 1 "recommended"
    else
        record_check "Privacy Controls" "Браузеры с телеметрией" "PASS" "Браузеры с повышенной телеметрией не обнаружены" "" 1 "recommended"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. ACCESS & AUTH
# ══════════════════════════════════════════════════════════════════════════════

check_access_auth() {
    print_section "4" "ACCESS & AUTHENTICATION"

    # ── 4.1 Пароль при выходе из скринсейвера ──
    local ask_pass
    ask_pass=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "not set")
    if [[ "$ask_pass" == "1" ]]; then
        record_check "Access & Auth" "Пароль при screensaver/sleep" "PASS" "Пароль запрашивается при выходе из скринсейвера/sleep" "" 4 "critical"
    else
        record_check "Access & Auth" "Пароль при screensaver/sleep" "FAIL" "Пароль не запрашивается — физический доступ к открытому Mac" "defaults write com.apple.screensaver askForPassword -int 1" 4 "critical"
    fi

    # ── 4.2 Задержка запроса пароля ──
    local ask_delay
    ask_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo "not set")
    if [[ "$ask_delay" == "0" ]]; then
        record_check "Access & Auth" "Задержка запроса пароля" "PASS" "Пароль запрашивается немедленно (0 секунд задержки)" "" 3 "important"
    elif [[ "$ask_delay" == "not set" ]]; then
        record_check "Access & Auth" "Задержка запроса пароля" "WARN" "Задержка запроса пароля не настроена" "defaults write com.apple.screensaver askForPasswordDelay -int 0" 3 "important"
    else
        record_check "Access & Auth" "Задержка запроса пароля" "FAIL" "Задержка ${ask_delay} сек — окно для несанкционированного доступа" "defaults write com.apple.screensaver askForPasswordDelay -int 0" 3 "important"
    fi

    # ── 4.3 Auto-login ──
    local auto_login
    auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "not set")
    if [[ "$auto_login" == "not set" ]]; then
        record_check "Access & Auth" "Auto-login" "PASS" "Автоматический вход отключён" "" 4 "critical"
    else
        record_check "Access & Auth" "Auto-login" "FAIL" "Автовход включён для пользователя: ${auto_login} — физический доступ = полный доступ" "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser" 4 "critical"
    fi

    # ── 4.4 Отображение подсказки пароля ──
    local show_hint
    show_hint=$(defaults read com.apple.loginwindow RetriesUntilHint 2>/dev/null || echo "not set")
    if [[ "$show_hint" == "0" || "$show_hint" == "not set" ]]; then
        record_check "Access & Auth" "Password Hints при логине" "PASS" "Подсказки пароля отключены" "" 2 "important"
    else
        record_check "Access & Auth" "Password Hints при логине" "WARN" "Подсказки пароля показываются после ${show_hint} попыток" "sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0" 2 "important"
    fi

    # ── 4.5 Показ имени пользователя в окне логина ──
    local login_window
    login_window=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null || echo "not set")
    if [[ "$login_window" == "1" ]]; then
        record_check "Access & Auth" "Окно логина: имя + пароль (вместо списка)" "PASS" "Вход через имя+пароль — не раскрывается список пользователей" "" 2 "recommended"
    else
        record_check "Access & Auth" "Окно логина: имя + пароль (вместо списка)" "WARN" "Окно логина показывает список пользователей — раскрывает имена аккаунтов" "sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true" 2 "recommended"
    fi

    # ── 4.6 Screen lock timeout ──
    local display_sleep
    display_sleep=$(pmset -g 2>/dev/null | grep "displaysleep" | awk '{print $2}' || echo "0")
    if [[ "$display_sleep" -le 5 && "$display_sleep" -gt 0 ]]; then
        record_check "Access & Auth" "Display sleep timeout" "PASS" "Экран гаснет через ${display_sleep} мин" "" 2 "important"
    elif [[ "$display_sleep" == "0" ]]; then
        record_check "Access & Auth" "Display sleep timeout" "WARN" "Экран никогда не гаснет автоматически" "sudo pmset -a displaysleep 2" 2 "important"
    else
        record_check "Access & Auth" "Display sleep timeout" "WARN" "Экран гаснет через ${display_sleep} мин — рекомендуется 2-5 мин" "sudo pmset -a displaysleep 2" 2 "important"
    fi

    # ── 4.7 Remote Login (SSH) ──
    local remote_login=""
    if [[ "$HAS_SUDO" == true ]]; then
        remote_login=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "")
    fi
    if echo "$remote_login" | grep -qi "off"; then
        record_check "Access & Auth" "Remote Login (SSH)" "PASS" "SSH отключён" "" 3 "important"
    elif echo "$remote_login" | grep -qi "on"; then
        record_check "Access & Auth" "Remote Login (SSH)" "FAIL" "SSH включён — удалённый доступ к терминалу открыт" "sudo systemsetup -setremotelogin off" 3 "important"
    else
        record_check "Access & Auth" "Remote Login (SSH)" "SKIP" "Не удалось проверить" "" 3 "important"
    fi

    # ── 4.8 Sudo timeout ──
    local sudo_timeout
    sudo_timeout=$(sudo cat /etc/sudoers 2>/dev/null | grep "timestamp_timeout" || echo "default (5 min)")
    record_check "Access & Auth" "Sudo timeout" "WARN" "Sudo timeout: ${sudo_timeout}. Рекомендуется уменьшить до 0-1 минут для безопасности." "Добавить в /etc/sudoers через visudo: Defaults timestamp_timeout=1" 1 "recommended"

    # ── 4.9 Find My Mac ──
    local find_my
    find_my=$(defaults read com.apple.FindMyMac FMMEnabled 2>/dev/null || nvram -x -p 2>/dev/null | grep -c "fmm-mobileme-token-FMM" || echo "not set")
    if [[ "$find_my" == "1" ]] || nvram -x -p 2>/dev/null | grep -q "fmm-mobileme-token-FMM"; then
        record_check "Access & Auth" "Find My Mac" "PASS" "Find My Mac включён — возможность удалённой блокировки/стирания" "" 3 "important"
    else
        record_check "Access & Auth" "Find My Mac" "WARN" "Find My Mac: статус не определён. Проверьте: System Settings → Apple ID → Find My" "" 3 "important"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. APPLICATION SECURITY
# ══════════════════════════════════════════════════════════════════════════════

check_application_security() {
    print_section "5" "APPLICATION SECURITY"

    # ── 5.1 Аудит Launch Agents (пользовательские) ──
    local user_agents_dir="${HOME}/Library/LaunchAgents"
    local suspicious_user_agents=()

    if [[ -d "$user_agents_dir" ]]; then
        while IFS= read -r agent; do
            [[ -z "$agent" ]] && continue
            local basename_agent
            basename_agent=$(basename "$agent")
            if ! is_trusted "$basename_agent"; then
                suspicious_user_agents+=("$basename_agent")
            fi
        done < <(find "$user_agents_dir" -name "*.plist" 2>/dev/null)
    fi

    if [[ ${#suspicious_user_agents[@]} -eq 0 ]]; then
        record_check "Application Security" "User Launch Agents" "PASS" "Нет подозрительных пользовательских Launch Agents" "" 3 "important"
    else
        local agent_list
        agent_list=$(printf ", %s" "${suspicious_user_agents[@]}")
        agent_list="${agent_list:2}"
        record_check "Application Security" "User Launch Agents" "WARN" "Нестандартные Launch Agents (не Apple/Mullvad/LuLu): ${agent_list}. Проверьте каждый вручную." "ls -la ~/Library/LaunchAgents/" 3 "important"
    fi

    # ── 5.2 Аудит Launch Agents (системные) ──
    local sys_agents_dir="/Library/LaunchAgents"
    local suspicious_sys_agents=()

    if [[ -d "$sys_agents_dir" ]]; then
        while IFS= read -r agent; do
            [[ -z "$agent" ]] && continue
            local basename_agent
            basename_agent=$(basename "$agent")
            if ! is_trusted "$basename_agent"; then
                suspicious_sys_agents+=("$basename_agent")
            fi
        done < <(find "$sys_agents_dir" -name "*.plist" 2>/dev/null)
    fi

    if [[ ${#suspicious_sys_agents[@]} -eq 0 ]]; then
        record_check "Application Security" "System Launch Agents" "PASS" "Нет подозрительных системных Launch Agents" "" 3 "important"
    else
        local agent_list
        agent_list=$(printf ", %s" "${suspicious_sys_agents[@]}")
        agent_list="${agent_list:2}"
        record_check "Application Security" "System Launch Agents" "WARN" "Нестандартные системные Launch Agents: ${agent_list}" "ls -la /Library/LaunchAgents/" 3 "important"
    fi

    # ── 5.3 Аудит Launch Daemons ──
    local sys_daemons_dir="/Library/LaunchDaemons"
    local suspicious_daemons=()

    if [[ -d "$sys_daemons_dir" ]]; then
        while IFS= read -r daemon; do
            [[ -z "$daemon" ]] && continue
            local basename_daemon
            basename_daemon=$(basename "$daemon")
            if ! is_trusted "$basename_daemon"; then
                suspicious_daemons+=("$basename_daemon")
            fi
        done < <(find "$sys_daemons_dir" -name "*.plist" 2>/dev/null)
    fi

    if [[ ${#suspicious_daemons[@]} -eq 0 ]]; then
        record_check "Application Security" "System Launch Daemons" "PASS" "Нет подозрительных Launch Daemons" "" 3 "important"
    else
        local daemon_list
        daemon_list=$(printf ", %s" "${suspicious_daemons[@]}")
        daemon_list="${daemon_list:2}"
        record_check "Application Security" "System Launch Daemons" "WARN" "Нестандартные Launch Daemons: ${daemon_list}" "ls -la /Library/LaunchDaemons/" 3 "important"
    fi

    # ── 5.4 Login Items ──
    local login_items
    login_items=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
    if [[ -n "$login_items" && "$login_items" != "" ]]; then
        record_check "Application Security" "Login Items" "WARN" "Login Items: ${login_items}. Проверьте необходимость каждого." "System Settings → General → Login Items" 2 "recommended"
    else
        record_check "Application Security" "Login Items" "PASS" "Нет пользовательских Login Items" "" 2 "recommended"
    fi

    # ── 5.5 Gatekeeper — разрешённые источники ──
    local gk_allow
    gk_allow=$(spctl --status 2>/dev/null || echo "")
    # Проверяем нет ли master-disable
    local gk_master_disabled=false
    if echo "$gk_allow" | grep -q "disabled"; then
        gk_master_disabled=true
    fi

    if [[ "$gk_master_disabled" == true ]]; then
        record_check "Application Security" "Gatekeeper: Allow Anywhere" "FAIL" "Gatekeeper полностью отключён (spctl --master-disable) — любые приложения могут запускаться" "sudo spctl --master-enable" 4 "critical"
    else
        record_check "Application Security" "Gatekeeper: Allow Anywhere" "PASS" "Gatekeeper активен — только подписанные приложения" "" 4 "critical"
    fi

    # ── 5.6 Quarantine awareness ──
    local quarantine_count
    quarantine_count=$(find ~/Downloads -maxdepth 1 -xattr 2>/dev/null | xargs -I{} xattr -l {} 2>/dev/null | grep -c "com.apple.quarantine" || echo "0")
    if [[ "$quarantine_count" -gt 0 ]]; then
        record_check "Application Security" "Quarantine (Downloads)" "WARN" "${quarantine_count} файлов с quarantine-флагом в ~/Downloads — потенциально непроверенные загрузки" "" 1 "recommended"
    else
        record_check "Application Security" "Quarantine (Downloads)" "PASS" "Нет файлов с quarantine-флагом в ~/Downloads" "" 1 "recommended"
    fi

    # ── 5.7 Objective-See Tools ──
    local objsee_tools=()
    [[ -d "/Applications/BlockBlock Helper.app" || -d "/Applications/BlockBlock.app" ]] && objsee_tools+=("BlockBlock")
    [[ -d "/Applications/OverSight.app" ]] && objsee_tools+=("OverSight")
    [[ -d "/Applications/KnockKnock.app" ]] && objsee_tools+=("KnockKnock")
    [[ -d "/Applications/RansomWhere.app" ]] && objsee_tools+=("RansomWhere?")

    if [[ ${#objsee_tools[@]} -gt 0 ]]; then
        local tools_list
        tools_list=$(printf ", %s" "${objsee_tools[@]}")
        tools_list="${tools_list:2}"
        record_check "Application Security" "Objective-See Security Tools" "PASS" "Установлены: ${tools_list}" "" 2 "recommended"
    else
        record_check "Application Security" "Objective-See Security Tools" "WARN" "Утилиты Objective-See не установлены. Рекомендуются: BlockBlock (persistence monitoring), KnockKnock (persistence audit), OverSight (camera/mic monitor)" "https://objective-see.org/tools.html" 2 "recommended"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 6. PERFORMANCE & HEALTH
# ══════════════════════════════════════════════════════════════════════════════

check_performance_health() {
    print_section "6" "PERFORMANCE & HEALTH"

    # ── 6.1 Memory Pressure ──
    local page_size
    page_size=$(sysctl -n hw.pagesize 2>/dev/null || echo "4096")
    local vm_stats
    vm_stats=$(vm_stat 2>/dev/null)
    local pages_free
    pages_free=$(echo "$vm_stats" | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
    local pages_active
    pages_active=$(echo "$vm_stats" | awk '/Pages active/ {gsub(/\./,"",$3); print $3}')
    local pages_inactive
    pages_inactive=$(echo "$vm_stats" | awk '/Pages inactive/ {gsub(/\./,"",$3); print $3}')
    local pages_wired
    pages_wired=$(echo "$vm_stats" | awk '/Pages wired/ {gsub(/\./,"",$4); print $4}')
    local pages_compressed
    pages_compressed=$(echo "$vm_stats" | awk '/Pages occupied by compressor/ {gsub(/\./,"",$5); print $5}')

    local total_mem_bytes
    total_mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
    local total_mem_gb
    total_mem_gb=$(echo "scale=1; $total_mem_bytes / 1073741824" | bc 2>/dev/null || echo "N/A")

    local used_pages=$((${pages_active:-0} + ${pages_wired:-0} + ${pages_compressed:-0}))
    local total_pages=$((used_pages + ${pages_free:-0} + ${pages_inactive:-0}))

    if [[ "$total_pages" -gt 0 ]]; then
        local mem_pressure=$((used_pages * 100 / total_pages))
        if [[ "$mem_pressure" -lt 75 ]]; then
            record_check "Performance" "Memory Pressure" "PASS" "Использование памяти: ~${mem_pressure}% (RAM: ${total_mem_gb} GB)" "" 2 "recommended"
        elif [[ "$mem_pressure" -lt 90 ]]; then
            record_check "Performance" "Memory Pressure" "WARN" "Высокое использование памяти: ~${mem_pressure}% (RAM: ${total_mem_gb} GB)" "" 2 "recommended"
        else
            record_check "Performance" "Memory Pressure" "FAIL" "Критическое использование памяти: ~${mem_pressure}% (RAM: ${total_mem_gb} GB) — возможна деградация производительности" "" 2 "recommended"
        fi
    fi

    # ── 6.2 Swap Usage ──
    local swap_info
    swap_info=$(sysctl vm.swapusage 2>/dev/null || echo "")
    local swap_used
    swap_used=$(echo "$swap_info" | awk '{for(i=1;i<=NF;i++) if ($i=="used") print $(i+2)}' | sed 's/M//')
    if [[ -n "$swap_used" ]]; then
        local swap_val
        swap_val=$(echo "$swap_used" | sed 's/\..*//')
        if [[ "${swap_val:-0}" -lt 1024 ]]; then
            record_check "Performance" "Swap Usage" "PASS" "Swap: ${swap_used}MB — в норме" "" 1 "recommended"
        else
            record_check "Performance" "Swap Usage" "WARN" "Swap: ${swap_used}MB — повышенное использование, возможна нехватка RAM" "" 1 "recommended"
        fi
    fi

    # ── 6.3 Disk Space ──
    local disk_usage
    disk_usage=$(df -H / 2>/dev/null | tail -1)
    local disk_percent
    disk_percent=$(echo "$disk_usage" | awk '{print $5}' | sed 's/%//')
    local disk_avail
    disk_avail=$(echo "$disk_usage" | awk '{print $4}')

    if [[ "${disk_percent:-0}" -lt 80 ]]; then
        record_check "Performance" "Disk Space" "PASS" "Диск: ${disk_percent}% занято, свободно ${disk_avail}" "" 2 "important"
    elif [[ "${disk_percent:-0}" -lt 95 ]]; then
        record_check "Performance" "Disk Space" "WARN" "Диск: ${disk_percent}% занято, свободно ${disk_avail} — рекомендуется освободить место" "" 2 "important"
    else
        record_check "Performance" "Disk Space" "FAIL" "Диск: ${disk_percent}% занято, свободно ${disk_avail} — критически мало места" "" 2 "important"
    fi

    # ── 6.4 User Caches ──
    local cache_size
    cache_size=$(du -sh ~/Library/Caches/ 2>/dev/null | awk '{print $1}' || echo "N/A")
    record_check "Performance" "User Caches" "WARN" "Размер ~/Library/Caches/: ${cache_size}" "rm -rf ~/Library/Caches/* (⚠ приложения пересоздадут кэши при следующем запуске)" 1 "recommended"

    # ── 6.5 APFS Snapshots (Time Machine) ──
    local snapshots
    snapshots=$(tmutil listlocalsnapshotdates 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    if [[ "${snapshots:-0}" -gt 10 ]]; then
        record_check "Performance" "Time Machine Local Snapshots" "WARN" "${snapshots} локальных снапшотов — могут занимать значительное место" "tmutil thinlocalsnapshots / \$(( \$(date +%s) - 86400 )) 1" 1 "recommended"
    else
        record_check "Performance" "Time Machine Local Snapshots" "PASS" "Локальных снапшотов: ${snapshots}" "" 1 "recommended"
    fi

    # ── 6.6 Battery Health (только ноутбуки) ──
    local battery_info
    battery_info=$(pmset -g batt 2>/dev/null || echo "")
    if echo "$battery_info" | grep -q "InternalBattery"; then
        local batt_percent
        batt_percent=$(echo "$battery_info" | grep -o '[0-9]*%' | head -1 | sed 's/%//')
        local batt_condition
        batt_condition=$(system_profiler SPPowerDataType 2>/dev/null | grep "Condition" | awk -F': ' '{print $2}' || echo "Unknown")
        local cycle_count
        cycle_count=$(system_profiler SPPowerDataType 2>/dev/null | grep "Cycle Count" | awk -F': ' '{print $2}' || echo "N/A")

        if [[ "$batt_condition" == "Normal" ]]; then
            record_check "Performance" "Battery Health" "PASS" "Батарея: ${batt_condition}, ${batt_percent}%, ${cycle_count} циклов" "" 1 "recommended"
        else
            record_check "Performance" "Battery Health" "WARN" "Батарея: ${batt_condition}, ${batt_percent}%, ${cycle_count} циклов" "" 1 "recommended"
        fi

        # ── 6.7 Optimized Battery Charging ──
        local optimized_charging
        optimized_charging=$(defaults read com.apple.smartcharging isEnabled 2>/dev/null || echo "not set")
        # На Apple Silicon может быть в другом месте
        if [[ "$optimized_charging" == "1" || "$optimized_charging" == "not set" ]]; then
            record_check "Performance" "Optimized Battery Charging" "PASS" "Оптимизированная зарядка активна (продлевает жизнь батареи)" "" 1 "recommended"
        else
            record_check "Performance" "Optimized Battery Charging" "WARN" "Оптимизированная зарядка отключена" "System Settings → Battery → Battery Health → Optimized Battery Charging" 1 "recommended"
        fi
    fi

    # ── 6.8 Uptime ──
    local uptime_days
    uptime_days=$(uptime 2>/dev/null | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')
    record_check "Performance" "System Uptime" "PASS" "Uptime: ${uptime_days}" "" 0 "info"
}

# ══════════════════════════════════════════════════════════════════════════════
# TCC PERMISSIONS AUDIT (бонус — если есть sudo)
# ══════════════════════════════════════════════════════════════════════════════

check_tcc_permissions() {
    if [[ "$HAS_SUDO" != true ]]; then
        return
    fi

    print_section "+" "TCC PERMISSIONS AUDIT (бонус)"

    local tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ ! -f "$tcc_db" ]]; then
        record_check "TCC Audit" "TCC Database" "SKIP" "TCC.db не найден" "" 0 "info"
        return
    fi

    # Проверяем ключевые разрешения
    local sensitive_services=("kTCCServiceCamera:Камера" "kTCCServiceMicrophone:Микрофон" "kTCCServiceScreenCapture:Запись экрана" "kTCCServiceSystemPolicyAllFiles:Полный доступ к диску" "kTCCServiceAccessibility:Accessibility" "kTCCServiceListenEvent:Input Monitoring")

    for service_pair in "${sensitive_services[@]}"; do
        local service_id="${service_pair%%:*}"
        local service_name="${service_pair##*:}"

        local apps_with_access
        apps_with_access=$(sudo sqlite3 "$tcc_db" "SELECT client FROM access WHERE service='${service_id}' AND auth_value=2;" 2>/dev/null || echo "")

        if [[ -n "$apps_with_access" ]]; then
            local app_count
            app_count=$(echo "$apps_with_access" | wc -l | tr -d ' ')
            local app_list
            app_list=$(echo "$apps_with_access" | tr '\n' ', ' | sed 's/,$//')
            record_check "TCC Audit" "TCC: ${service_name}" "WARN" "${app_count} приложений с доступом: ${app_list}" "System Settings → Privacy & Security → ${service_name}" 2 "important"
        else
            record_check "TCC Audit" "TCC: ${service_name}" "PASS" "Нет приложений с доступом к ${service_name}" "" 2 "important"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# ГЕНЕРАЦИЯ HTML-ОТЧЁТА
# ══════════════════════════════════════════════════════════════════════════════

calculate_score() {
    local total_weight=0
    local earned_weight=0

    for result in "${RESULTS_JSON[@]}"; do
        local weight
        weight=$(echo "$result" | sed 's/.*"weight":\([0-9]*\).*/\1/')
        local status
        status=$(echo "$result" | sed 's/.*"status":"\([A-Z]*\)".*/\1/')

        if [[ "$status" == "SKIP" ]]; then
            continue
        fi

        total_weight=$((total_weight + weight))
        if [[ "$status" == "PASS" ]]; then
            earned_weight=$((earned_weight + weight))
        elif [[ "$status" == "WARN" ]]; then
            earned_weight=$((earned_weight + weight / 2))
        fi
    done

    if [[ "$total_weight" -gt 0 ]]; then
        echo $((earned_weight * 100 / total_weight))
    else
        echo 0
    fi
}

generate_html_report() {
    local score
    score=$(calculate_score)

    local score_color="#22c55e"  # green
    local score_label="Отлично"
    if [[ "$score" -lt 50 ]]; then
        score_color="#ef4444"  # red
        score_label="Критично"
    elif [[ "$score" -lt 70 ]]; then
        score_color="#f59e0b"  # yellow
        score_label="Требует внимания"
    elif [[ "$score" -lt 85 ]]; then
        score_color="#3b82f6"  # blue
        score_label="Хорошо"
    fi

    # Начинаем генерацию HTML
    cat > "$REPORT_FILE" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>macOS Security Audit Report</title>
<style>
:root {
    --bg-primary: #0a0a0b;
    --bg-secondary: #111113;
    --bg-card: #16161a;
    --bg-hover: #1c1c21;
    --border: #252529;
    --border-light: #2a2a2f;
    --text-primary: #e4e4e7;
    --text-secondary: #a1a1aa;
    --text-dim: #71717a;
    --accent: #a78bfa;
    --pass: #22c55e;
    --pass-bg: rgba(34, 197, 94, 0.08);
    --fail: #ef4444;
    --fail-bg: rgba(239, 68, 68, 0.08);
    --warn: #f59e0b;
    --warn-bg: rgba(245, 158, 11, 0.08);
    --skip: #52525b;
    --skip-bg: rgba(82, 82, 91, 0.08);
    --font-sans: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Inter', system-ui, sans-serif;
    --font-mono: 'SF Mono', 'Fira Code', 'JetBrains Mono', 'Consolas', monospace;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: var(--font-sans);
    line-height: 1.6;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
}

.container {
    max-width: 960px;
    margin: 0 auto;
    padding: 40px 24px 80px;
}

/* Header */
.header {
    text-align: center;
    margin-bottom: 48px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
}

.header h1 {
    font-size: 28px;
    font-weight: 600;
    letter-spacing: -0.5px;
    margin-bottom: 16px;
    color: var(--text-primary);
}

.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px 24px;
    font-size: 13px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
}

.meta-grid span { opacity: 0.6; }
.meta-grid strong { color: var(--text-primary); opacity: 1; font-weight: 500; }

/* Score Ring */
.score-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin: 40px 0;
}

.score-ring {
    position: relative;
    width: 160px;
    height: 160px;
}

.score-ring svg {
    transform: rotate(-90deg);
    width: 160px;
    height: 160px;
}

.score-ring circle {
    fill: none;
    stroke-width: 8;
    stroke-linecap: round;
}

.score-bg { stroke: var(--border); }

.score-value-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}

.score-number {
    font-size: 42px;
    font-weight: 700;
    letter-spacing: -2px;
    line-height: 1;
}

.score-label {
    font-size: 12px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-top: 4px;
}

/* Summary Cards */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin: 32px 0 48px;
}

.summary-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
}

.summary-card .count {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -1px;
}

.summary-card .label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text-dim);
    margin-top: 4px;
}

/* Sections */
.section {
    margin-bottom: 32px;
}

.section-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    margin-bottom: 8px;
    border-bottom: 1px solid var(--border);
}

.section-header h2 {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
}

.section-num {
    background: var(--bg-hover);
    color: var(--text-dim);
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: var(--font-mono);
}

/* Check Items */
.check-item {
    display: grid;
    grid-template-columns: 72px 1fr;
    gap: 0;
    padding: 12px 0;
    border-bottom: 1px solid var(--bg-hover);
    align-items: start;
}

.check-item:last-child { border-bottom: none; }

.status-badge {
    font-size: 11px;
    font-weight: 600;
    font-family: var(--font-mono);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 3px 8px;
    border-radius: 4px;
    text-align: center;
    width: fit-content;
}

.status-pass { color: var(--pass); background: var(--pass-bg); }
.status-fail { color: var(--fail); background: var(--fail-bg); }
.status-warn { color: var(--warn); background: var(--warn-bg); }
.status-skip { color: var(--skip); background: var(--skip-bg); }

.check-body h3 {
    font-size: 14px;
    font-weight: 500;
    margin-bottom: 4px;
}

.check-detail {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
}

.check-fix {
    margin-top: 6px;
    padding: 6px 10px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent);
    word-break: break-all;
    cursor: pointer;
    position: relative;
    transition: border-color 0.2s;
}

.check-fix:hover { border-color: var(--accent); }

.check-fix::after {
    content: 'click to copy';
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 10px;
    color: var(--text-dim);
    opacity: 0;
    transition: opacity 0.2s;
}

.check-fix:hover::after { opacity: 1; }

/* Quick Fix Section */
.quickfix {
    margin-top: 48px;
    padding: 24px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
}

.quickfix h2 {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--fail);
}

.quickfix-block {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.8;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-all;
    cursor: pointer;
    position: relative;
}

.quickfix-block:hover { border-color: var(--accent); }

.copy-hint {
    position: absolute;
    top: 8px;
    right: 12px;
    font-size: 10px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* Manual Recommendations */
.manual-recs {
    margin-top: 32px;
    padding: 24px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
}

.manual-recs h2 {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--accent);
}

.manual-recs ul {
    list-style: none;
    padding: 0;
}

.manual-recs li {
    padding: 8px 0;
    border-bottom: 1px solid var(--bg-hover);
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.6;
}

.manual-recs li:last-child { border-bottom: none; }
.manual-recs li strong { color: var(--text-primary); }

/* Footer */
.footer {
    text-align: center;
    margin-top: 48px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-dim);
}

@media (max-width: 640px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .check-item { grid-template-columns: 64px 1fr; }
    .meta-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    # Header
    cat >> "$REPORT_FILE" << HTMLMETA
<div class="header">
<h1>macOS Security Audit</h1>
<div class="meta-grid">
<div><span>Host:</span> <strong>${HOSTNAME_VAL}</strong></div>
<div><span>macOS:</span> <strong>${MACOS_VERSION} (${MACOS_BUILD})</strong></div>
<div><span>Model:</span> <strong>${HARDWARE_MODEL}</strong></div>
<div><span>Chip:</span> <strong>${CHIP}</strong></div>
<div><span>Arch:</span> <strong>${ARCH}</strong></div>
<div><span>Date:</span> <strong>${AUDIT_DATE}</strong></div>
<div><span>Serial:</span> <strong>${SERIAL}</strong></div>
<div><span>Script:</span> <strong>v${SCRIPT_VERSION}</strong></div>
</div>
</div>
HTMLMETA

    # Score Ring
    local circumference=452  # 2 * PI * 72
    local dash_offset=$((circumference - (circumference * score / 100)))

    cat >> "$REPORT_FILE" << HTMLSCORE
<div class="score-section">
<div class="score-ring">
<svg viewBox="0 0 160 160">
<circle class="score-bg" cx="80" cy="80" r="72"/>
<circle class="score-fg" cx="80" cy="80" r="72"
    stroke="${score_color}" stroke-dasharray="${circumference}" stroke-dashoffset="${dash_offset}"/>
</svg>
<div class="score-value-text">
<div class="score-number" style="color:${score_color}">${score}</div>
<div class="score-label">${score_label}</div>
</div>
</div>
</div>

<div class="summary-grid">
<div class="summary-card"><div class="count" style="color:var(--pass)">${PASS_COUNT}</div><div class="label">Pass</div></div>
<div class="summary-card"><div class="count" style="color:var(--fail)">${FAIL_COUNT}</div><div class="label">Fail</div></div>
<div class="summary-card"><div class="count" style="color:var(--warn)">${WARN_COUNT}</div><div class="label">Warn</div></div>
<div class="summary-card"><div class="count" style="color:var(--skip)">${SKIP_COUNT}</div><div class="label">Skip</div></div>
</div>
HTMLSCORE

    # Генерируем секции по категориям
    local current_category=""
    local section_num=0
    local section_names=("System Integrity" "Network Security" "Privacy Controls" "Access & Auth" "Application Security" "Performance" "TCC Audit")

    for result in "${RESULTS_JSON[@]}"; do
        local cat
        cat=$(echo "$result" | sed 's/.*"category":"\([^"]*\)".*/\1/')
        local name
        name=$(echo "$result" | sed 's/.*"name":"\([^"]*\)".*/\1/')
        local status
        status=$(echo "$result" | sed 's/.*"status":"\([^"]*\)".*/\1/')
        local detail
        detail=$(echo "$result" | sed 's/.*"detail":"\([^"]*\)".*/\1/')
        local fix
        fix=$(echo "$result" | sed 's/.*"fix":"\([^"]*\)".*/\1/')

        if [[ "$cat" != "$current_category" ]]; then
            if [[ -n "$current_category" ]]; then
                echo "</div>" >> "$REPORT_FILE"
            fi
            current_category="$cat"
            section_num=$((section_num + 1))
            cat >> "$REPORT_FILE" << HTMLSEC
<div class="section">
<div class="section-header">
<span class="section-num">${section_num}</span>
<h2>${cat}</h2>
</div>
HTMLSEC
        fi

        local status_class="status-pass"
        case "$status" in
            FAIL) status_class="status-fail" ;;
            WARN) status_class="status-warn" ;;
            SKIP) status_class="status-skip" ;;
        esac

        cat >> "$REPORT_FILE" << HTMLCHECK
<div class="check-item">
<div><span class="status-badge ${status_class}">${status}</span></div>
<div class="check-body">
<h3>${name}</h3>
<div class="check-detail">${detail}</div>
HTMLCHECK

        if [[ -n "$fix" && "$fix" != "" ]]; then
            echo "<div class=\"check-fix\" onclick=\"navigator.clipboard.writeText(this.textContent.replace('click to copy','').trim())\">${fix}</div>" >> "$REPORT_FILE"
        fi

        echo "</div></div>" >> "$REPORT_FILE"
    done

    # Закрываем последнюю секцию
    if [[ -n "$current_category" ]]; then
        echo "</div>" >> "$REPORT_FILE"
    fi

    # Quick Fix Block
    if [[ ${#QUICK_FIXES[@]} -gt 0 ]]; then
        echo '<div class="quickfix">' >> "$REPORT_FILE"
        echo '<h2>⚡ Quick Fix — все команды исправления</h2>' >> "$REPORT_FILE"
        echo '<div class="quickfix-block" onclick="navigator.clipboard.writeText(this.textContent.replace('"'"'Click to copy all'"'"','"'"''"'"').trim())">' >> "$REPORT_FILE"
        echo '<span class="copy-hint">Click to copy all</span>' >> "$REPORT_FILE"
        for qf in "${QUICK_FIXES[@]}"; do
            local comment="${qf%%|*}"
            local cmd="${qf##*|}"
            echo "${comment}" >> "$REPORT_FILE"
            echo "${cmd}" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        done
        echo '</div></div>' >> "$REPORT_FILE"
    fi

    # Manual Recommendations
    cat >> "$REPORT_FILE" << 'HTMLMANUAL'
<div class="manual-recs">
<h2>📋 Рекомендации (ручная настройка)</h2>
<ul>
<li><strong>Браузер:</strong> Если используете Firefox — установите arkenfox/user.js для privacy hardening. В about:config: media.peerconnection.enabled=false (WebRTC leak), privacy.resistFingerprinting=true</li>
<li><strong>DuckDuckGo Browser:</strong> Рекомендуется для повседневного браузинга. Встроенная защита от трекеров, принудительный HTTPS, fire button для очистки данных</li>
<li><strong>Отдельный browser profile:</strong> Для криптоопераций используйте отдельный браузер/профиль — никогда не смешивайте с повседневным браузингом</li>
<li><strong>Password Manager:</strong> Используйте Bitwarden или 1Password. Master password: 4+ diceware-слов, уникальный. Включите TOTP или FIDO2 для vault</li>
<li><strong>MFA:</strong> Для критичного (email, crypto, Apple ID) — FIDO2 hardware key (YubiKey). Для остального — TOTP (Ente Auth). Отключите SMS MFA везде где возможно</li>
<li><strong>Apple ID:</strong> Включите Advanced Data Protection (E2E encryption для iCloud). Привяжите 2x YubiKey к Apple ID</li>
<li><strong>Signal:</strong> Настройте disappearing messages по умолчанию, Registration Lock, Screen Lock</li>
<li><strong>Objective-See:</strong> Установите BlockBlock (мониторинг persistence), KnockKnock (аудит persistence), OverSight (алерты камеры/микрофона)</li>
<li><strong>Backup:</strong> Time Machine на зашифрованный внешний диск. Тестируйте restore раз в квартал</li>
<li><strong>Mullvad:</strong> Проверьте: WireGuard протокол, Kill Switch = Always require VPN, DAITA включён, DNS blocking (ads + trackers + malware)</li>
<li><strong>Mullvad Leak Test:</strong> Регулярно проверяйте: mullvad.net/check, dnsleaktest.com (extended), browserleaks.com/webrtc</li>
</ul>
</div>
HTMLMANUAL

    # Footer
    cat >> "$REPORT_FILE" << HTMLFOOTER
<div class="footer">
macOS Security Audit Tool v${SCRIPT_VERSION} · ${AUDIT_DATE} · ${HOSTNAME_VAL}
</div>
</div>

<script>
// Click-to-copy для fix-команд
document.querySelectorAll('.check-fix').forEach(el => {
    el.addEventListener('click', function() {
        const text = this.textContent.replace('click to copy', '').trim();
        navigator.clipboard.writeText(text).then(() => {
            const orig = this.style.borderColor;
            this.style.borderColor = 'var(--pass)';
            setTimeout(() => this.style.borderColor = orig, 800);
        });
    });
});
</script>
</body>
</html>
HTMLFOOTER
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

main() {
    clear
    print_banner

    # Запрос sudo
    HAS_SUDO=false
    request_sudo

    echo ""
    echo -e "${BOLD}Запуск аудита...${NC}"

    # Запуск всех проверок
    check_system_integrity
    check_network_security
    check_privacy_controls
    check_access_auth
    check_application_security
    check_performance_health
    check_tcc_permissions

    # Генерация HTML-отчёта
    echo ""
    echo -e "${BOLD}${CYAN}Генерация HTML-отчёта...${NC}"
    generate_html_report

    # Финальная сводка
    local score
    score=$(calculate_score)

    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  РЕЗУЛЬТАТЫ АУДИТА${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Security Score: ${BOLD}${score}/100${NC}"
    echo -e "  ${GREEN}PASS: ${PASS_COUNT}${NC}  ${RED}FAIL: ${FAIL_COUNT}${NC}  ${YELLOW}WARN: ${WARN_COUNT}${NC}  ${DIM}SKIP: ${SKIP_COUNT}${NC}"
    echo -e "  Всего проверок: ${TOTAL_CHECKS}"
    echo ""
    echo -e "  HTML-отчёт: ${BOLD}${REPORT_FILE}${NC}"
    echo ""

    # Открыть отчёт
    open "$REPORT_FILE" 2>/dev/null || true

    # Убить фоновый sudo-keeper
    if [[ -n "${SUDO_KEEPER_PID:-}" ]]; then
        kill "$SUDO_KEEPER_PID" 2>/dev/null || true
    fi
}

main "$@"
