#!/usr/bin/env bash
#
# php2shell-fix.sh — one-command fix for PHP2Shell
#                    CVE-2026-109618 and CVE-2026-109619 (disclosed 21 Oct 2026)
#
# Fixed upstream in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
#
# It always takes the least invasive fix that works, and only escalates
# when the step below it fails:
#
#   1. Find every PHP on the machine: distro packages, cPanel/CloudLinux/
#      Plesk builds, Remi SCL, LiteSpeed lsphp, Homebrew, source builds,
#      FrankenPHP and running Docker containers (Docker is report-only).
#   2. Check each one: upstream version, or the distro changelog for a
#      backported fix. Safe installs are left alone.
#   3. Upgrade only that branch's PHP packages from the repos already set up.
#   4. No fix there? Add Ondrej Sury's repo (Debian/Ubuntu) or Remi's repo
#      (RHEL/Alma/Rocky/Oracle 8 and 9) and patch the SAME branch.
#   5. --force: move what is still vulnerable to a supported branch
#      (default 8.3). --project scans your code with PHPCompatibility first.
#   6. Whatever is still vulnerable gets a temporary php.ini mitigation.
#   7. Restart PHP-FPM / Apache / LiteSpeed and confirm no process still
#      runs the old binary.
#
# Usage
#   curl -fsSL https://php2shell.wizeb.com/autofix | sudo bash
#   curl -fsSL https://php2shell.wizeb.com/autofix | sudo bash -s -- --force --project /var/www/app
#   macOS (Homebrew): run it WITHOUT sudo.
#
# Run with --help for all options.

VERSION="1.0.0"
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"
SUPPORTED_BRANCHES="8.2 8.3 8.4 8.5"
DEFAULT_TARGET="8.3"
MITIG_NAME="99-php2shell-mitigation.ini"
MARKER="php2shell-fix"

ORIG_ARGS=("$@")

# ---------------------------------------------------------------- options --

usage() {
  cat <<'EOF'
php2shell-fix.sh — find and fix PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

Usage:  sudo bash php2shell-fix.sh [options]        (macOS/Homebrew: no sudo)

  (no options)        Patch every vulnerable PHP with the least invasive fix,
                      apply a temporary mitigation to anything left, restart PHP.
  -n, --dry-run       Only report what is vulnerable and what would be done.
  -f, --force         Also move PHP that cannot be patched in place (EOL
                      branches) to a supported branch. Old branch stays
                      installed but stops serving. MAY BREAK OLD APPS.
  -t, --target X.Y    Branch to move to with --force (8.2-8.5, default 8.3).
  -p, --project DIR   Scan DIR with PHPCompatibility for the target branch
                      before forcing (repeatable). Needs internet (Composer).
  -y, --yes           Don't pause before --force changes.
      --no-restart    Don't restart PHP-FPM / web servers.
      --no-mitigate   Don't add the temporary php.ini mitigation.
      --no-docker     Don't inspect running Docker containers.
      --rollback      Undo the --force changes of the last run.
  -h, --help          Show this help.   -V, --version   Show version.

Exit codes: 0 = everything safe, 1 = something still needs attention, 2 = error.
Log: /var/log/php2shell-fix.log (macOS: ~/Library/Logs/php2shell-fix.log)
EOF
}

DRY_RUN=0; FORCE=0; TARGET=""; ASSUME_YES=0; DO_RESTART=1; DO_MITIGATE=1
DO_DOCKER=1; ROLLBACK=0
PROJECTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run|--check) DRY_RUN=1 ;;
    -f|--force)           FORCE=1 ;;
    -t|--target)          TARGET="${2:-}"; shift ;;
    --target=*)           TARGET="${1#*=}" ;;
    -p|--project)         PROJECTS[${#PROJECTS[@]}]="${2:-}"; shift ;;
    --project=*)          PROJECTS[${#PROJECTS[@]}]="${1#*=}" ;;
    -y|--yes)             ASSUME_YES=1 ;;
    --no-restart)         DO_RESTART=0 ;;
    --no-mitigate)        DO_MITIGATE=0 ;;
    --no-docker)          DO_DOCKER=0 ;;
    --rollback)           ROLLBACK=1 ;;
    -h|--help)            usage; exit 0 ;;
    -V|--version)         echo "$VERSION"; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  [ $# -gt 0 ] && shift
done

# ----------------------------------------------------------------- output --

if [ -t 1 ]; then
  B=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'
  CYN=$'\033[36m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  B=""; RED=""; GRN=""; YEL=""; CYN=""; DIM=""; RST=""
fi

LOG_FILE=""
log()  { [ -n "$LOG_FILE" ] && printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG_FILE" 2>/dev/null; return 0; }
step() { printf '\n%s==> %s%s\n' "$B$CYN" "$*" "$RST"; log "==> $*"; }
info() { printf '  %s\n' "$*"; log "  $*"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; log "  OK   $*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$RST" "$*"; log "  WARN $*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*"; log "  BAD  $*"; }
die()  { printf '%sError:%s %s\n' "$RED" "$RST" "$*" >&2; log "FATAL $*"; exit 2; }

# Run a command that changes the system. Output goes to the log.
run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '  %s[dry-run]%s %s\n' "$DIM" "$RST" "$*"; log "DRY  $*"; return 0
  fi
  printf '  %s$ %s%s\n' "$DIM" "$*" "$RST"
  log "RUN  $*"
  local rc
  if [ -n "$LOG_FILE" ]; then "$@" >>"$LOG_FILE" 2>&1 </dev/null; rc=$?
  else "$@" >/dev/null 2>&1 </dev/null; rc=$?; fi
  [ $rc -ne 0 ] && log "     exit code $rc"
  return $rc
}

# Run a read-only command with a time limit when a timeout tool exists.
run_t() {
  local s="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$s" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$s" "$@"
  else "$@"; fi
}

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else return 1; fi
}

# ------------------------------------------------------- version helpers --

# Prints -1, 0 or 1. Pure bash so it works with macOS bash 3.2.
ver_cmp() {
  local IFS=. i x y
  local -a A BB
  # shellcheck disable=SC2206
  A=($1)
  # shellcheck disable=SC2206
  BB=($2)
  for i in 0 1 2 3; do
    x=${A[$i]:-0}; y=${BB[$i]:-0}
    x=${x%%[!0-9]*}; y=${y%%[!0-9]*}
    x=${x:-0}; y=${y:-0}
    if [ "$((10#$x))" -gt "$((10#$y))" ]; then echo 1; return; fi
    if [ "$((10#$x))" -lt "$((10#$y))" ]; then echo -1; return; fi
  done
  echo 0
}
ver_ge() { [ "$(ver_cmp "$1" "$2")" != "-1" ]; }

# Fixed release for a branch; empty for end-of-life branches; "new" for
# branches released after the fix.
fixed_for() {
  case "$1" in
    8.2) echo 8.2.35 ;; 8.3) echo 8.3.36 ;; 8.4) echo 8.4.27 ;; 8.5) echo 8.5.12 ;;
    *) if [ -n "$1" ] && [ "$(ver_cmp "$1" 8.5)" = 1 ]; then echo new; fi ;;
  esac
}

branch_of() { printf '%s\n' "$1" | cut -d. -f1,2; }

# Version of a PHP binary (php, php-fpm, php-cgi, lsphp, frankenphp).
php_version() {
  local bin="$1" out
  [ -n "$bin" ] && [ -x "$bin" ] || return 1
  case "${bin##*/}" in
    frankenphp*) out=$(run_t 15 "$bin" version 2>/dev/null) ;;
    *)           out=$(run_t 15 "$bin" -n -v 2>/dev/null) ;;
  esac
  out=$(printf '%s\n' "$out" | sed -n 's/.*PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n1)
  [ -n "$out" ] && echo "$out"
}

# Branch to move to with --force: the target if it is newer, otherwise the
# next supported branch above the current one.
target_for() {
  local b="$1" t="${TARGET:-$DEFAULT_TARGET}" s
  if [ "$(ver_cmp "$t" "$b")" = 1 ]; then echo "$t"; return; fi
  for s in $SUPPORTED_BRANCHES; do
    [ "$(ver_cmp "$s" "$b")" = 1 ] && { echo "$s"; return; }
  done
}

# Portable realpath (macOS may lack readlink -f).
resolve_path() {
  local p="$1" l n=0 d
  while [ -L "$p" ] && [ $n -lt 40 ]; do
    l=$(readlink "$p")
    case "$l" in /*) p="$l" ;; *) p="$(dirname "$p")/$l" ;; esac
    n=$((n + 1))
  done
  d=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd) || { echo "$p"; return; }
  echo "$d/${p##*/}"
}

# shellcheck disable=SC2048,SC2086
uniq_words() { printf '%s\n' $* | sed '/^$/d' | sort -u | tr '\n' ' '; }

# --------------------------------------------------------- environment --

OS=""; OS_ID=""; OS_LIKE=""; OS_VER=""; OS_CODENAME=""; UBU_CODENAME=""; OS_NAME=""
FAMILY=""; PM="none"; EL=""; BREW_BIN=""; BREW_USER=""; BREW_PREFIX=""; UHOME="$HOME"

detect_os() {
  if [ "$(uname -s)" = Darwin ]; then
    OS=mac; FAMILY=mac
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null)"
    BREW_BIN=$(command -v brew 2>/dev/null)
    [ -z "$BREW_BIN" ] && [ -x /opt/homebrew/bin/brew ] && BREW_BIN=/opt/homebrew/bin/brew
    [ -z "$BREW_BIN" ] && [ -x /usr/local/bin/brew ] && BREW_BIN=/usr/local/bin/brew
    if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
      BREW_USER="$SUDO_USER"
      UHOME=$(eval echo "~$SUDO_USER")
    fi
    if [ -n "$BREW_BIN" ]; then
      PM=brew
      BREW_PREFIX=$(brew_cmd --prefix 2>/dev/null)
    fi
    return
  fi

  OS=linux
  if [ -r /etc/os-release ]; then
    OS_ID=$(. /etc/os-release; echo "${ID:-}")
    OS_LIKE=$(. /etc/os-release; echo "${ID_LIKE:-}")
    OS_VER=$(. /etc/os-release; echo "${VERSION_ID:-}")
    OS_CODENAME=$(. /etc/os-release; echo "${VERSION_CODENAME:-}")
    UBU_CODENAME=$(. /etc/os-release; echo "${UBUNTU_CODENAME:-}")
    OS_NAME=$(. /etc/os-release; echo "${PRETTY_NAME:-$ID}")
  fi
  [ -z "$OS_NAME" ] && OS_NAME="Linux"
  if   command -v apt-get >/dev/null 2>&1; then PM=apt
  elif command -v dnf     >/dev/null 2>&1; then PM=dnf
  elif command -v yum     >/dev/null 2>&1; then PM=yum
  elif command -v zypper  >/dev/null 2>&1; then PM=zypper
  elif command -v apk     >/dev/null 2>&1; then PM=apk
  elif command -v pacman  >/dev/null 2>&1; then PM=pacman
  fi
  case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*)                       FAMILY=debian ;;
    *" fedora "*)  [ "$OS_ID" = fedora ] && FAMILY=fedora || FAMILY=rhel ;;
    *" rhel "*|*" centos "*)                         FAMILY=rhel ;;
    *suse*)                                          FAMILY=suse ;;
    *" alpine "*)                                    FAMILY=alpine ;;
    *" arch "*)                                      FAMILY=arch ;;
  esac
  case "$OS_ID" in rhel|centos|rocky|almalinux|ol|eurolinux|cloudlinux|virtuozzo) FAMILY=rhel ;; esac
  [ "$FAMILY" = rhel ] && EL="${OS_VER%%.*}"
}

is_ubuntu() { case " $OS_ID $OS_LIKE " in *" ubuntu "*) return 0 ;; esac; return 1; }
has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

brew_cmd() {
  if [ -n "$BREW_USER" ]; then
    sudo -u "$BREW_USER" -H env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 \
      HOMEBREW_NO_ENV_HINTS=1 "$BREW_BIN" "$@"
  else
    HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1 "$BREW_BIN" "$@"
  fi
}

# ------------------------------------------------------------- registry --
# One record per PHP installation, kept in parallel arrays (bash 3.2 has no
# associative arrays).

N=0
KNOWN_PKGS=" "; KNOWN_BINS="|"; ALL_PKGS=""
I_KIND=(); I_PM=(); I_BRANCH=(); I_BIN=(); I_PKGS=(); I_COMMON=(); I_LABEL=()
I_BEFORE=(); I_AFTER=(); I_STATE=(); I_WHY=(); I_HOW=(); I_NOTE=(); I_MITIG=()

add_install() { # kind pm branch bin pkgs common label
  I_KIND[$N]="$1"; I_PM[$N]="$2"; I_BRANCH[$N]="$3"; I_BIN[$N]="$4"
  I_PKGS[$N]="$5"; I_COMMON[$N]="$6"; I_LABEL[$N]="$7"
  I_BEFORE[$N]=""; I_AFTER[$N]=""; I_STATE[$N]=""; I_WHY[$N]=""; I_HOW[$N]=""
  I_NOTE[$N]=""; I_MITIG[$N]=0
  KNOWN_PKGS="$KNOWN_PKGS$5 "
  [ -n "$4" ] && case "$4" in docker:*) ;; *) KNOWN_BINS="$KNOWN_BINS$(resolve_path "$4")|" ;; esac
  N=$((N + 1))
}

needs() { I_STATE[$1]=NEEDS; I_NOTE[$1]="$2"; }

first_in() { # list candidates... -> first candidate present in list
  local list="$1" c; shift
  for c in "$@"; do printf '%s\n' "$list" | grep -qx "$c" && { echo "$c"; return; }; done
}

# ------------------------------------------------------------ discovery --

deb_installed() {
  dpkg-query -W -f='${Status}|${Package}\n' 2>/dev/null | awk -F'|' '$1 ~ / installed$/ {print $2}'
}

esc_dots() { printf '%s' "$1" | sed 's/\./\\./g'; }

discover_deb() {
  local b e pkgs bin c
  ALL_PKGS=$(deb_installed)
  for b in $(printf '%s\n' "$ALL_PKGS" | sed -n 's/^php\([0-9][0-9]*\.[0-9][0-9]*\)-common$/\1/p' | sort -u); do
    e=$(esc_dots "$b")
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E "^(php${e}(-.*)?|libapache2-mod-php${e})\$" | tr '\n' ' ')
    bin=""
    for c in /usr/bin/php$b /usr/sbin/php-fpm$b /usr/bin/php-cgi$b; do [ -x "$c" ] && { bin=$c; break; }; done
    add_install deb apt "$b" "$bin" "$pkgs" "php$b-common" "PHP $b (apt)"
  done
  if printf '%s\n' "$ALL_PKGS" | grep -qx php5-common; then
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E '^(php5(-.*)?|libapache2-mod-php5)$' | tr '\n' ' ')
    add_install deb apt 5 /usr/bin/php5 "$pkgs" php5-common "PHP 5 (apt)"
  fi
  discover_panels apt
}

discover_rpm() {
  local base bin c nn b pkgs
  ALL_PKGS=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort -u)
  base=$(printf '%s\n' "$ALL_PKGS" | grep -E '^(php[0-9]?(-.*)?|apache2-mod_php[0-9]*)$' | tr '\n' ' ')
  if [ -n "${base// /}" ]; then
    bin=""
    for c in /usr/bin/php /usr/bin/php8 /usr/bin/php7 /usr/sbin/php-fpm /usr/bin/php-cgi; do
      [ -x "$c" ] && { bin=$c; break; }
    done
    c=$(first_in "$ALL_PKGS" php-common php8 php7 php-cli php)
    add_install rpm "$PM" "" "$bin" "$base" "$c" "PHP (system, $PM)"
  fi
  for nn in $(printf '%s\n' "$ALL_PKGS" | sed -n 's/^php\([0-9][0-9]\)-php-common$/\1/p'); do
    b="${nn%?}.${nn#?}"
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E "^php${nn}(-|\$)" | tr '\n' ' ')
    add_install rpm-scl "$PM" "$b" "/opt/remi/php$nn/root/usr/bin/php" "$pkgs" "php$nn-php-common" "PHP $b (Remi php$nn)"
  done
  discover_panels "$PM"
}

discover_panels() { # cPanel EasyApache, CloudLinux alt-php, Plesk
  local pm="$1" nn b pkgs c
  for nn in $(printf '%s\n' "$ALL_PKGS" | sed -n 's/^ea-php\([0-9][0-9]\)$/\1/p'); do
    b="${nn%?}.${nn#?}"
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E "^ea-php${nn}(-|\$)" | tr '\n' ' ')
    c=$(first_in "$ALL_PKGS" "ea-php$nn-php-common" "ea-php$nn-php-cli" "ea-php$nn")
    add_install panel "$pm" "$b" "/opt/cpanel/ea-php$nn/root/usr/bin/php" "$pkgs" "$c" "cPanel ea-php$nn"
  done
  for nn in $(printf '%s\n' "$ALL_PKGS" | sed -n 's/^alt-php\([0-9][0-9]\)$/\1/p'); do
    b="${nn%?}.${nn#?}"
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E "^alt-php${nn}(-|\$)" | tr '\n' ' ')
    add_install panel "$pm" "$b" "/opt/alt/php$nn/usr/bin/php" "$pkgs" "alt-php$nn" "CloudLinux alt-php$nn"
  done
  for nn in $(printf '%s\n' "$ALL_PKGS" | sed -n 's/^plesk-php\([0-9][0-9]\)$/\1/p'); do
    b="${nn%?}.${nn#?}"
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E "^plesk-php${nn}(-|\$)" | tr '\n' ' ')
    add_install panel "$pm" "$b" "/opt/plesk/php/$b/bin/php" "$pkgs" "plesk-php$nn" "Plesk PHP $b"
  done
}

discover_apk() {
  local nn b pkgs bin
  ALL_PKGS=$(apk info 2>/dev/null)
  for nn in $(printf '%s\n' "$ALL_PKGS" | sed -n 's/^php\([0-9][0-9]\)$/\1/p' | sort -u); do
    b="${nn%?}.${nn#?}"
    pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E "^php${nn}(-|\$)" | tr '\n' ' ')
    bin=/usr/bin/php$nn; [ -x "$bin" ] || bin=/usr/sbin/php-fpm$nn
    add_install apk apk "$b" "$bin" "$pkgs" "php$nn" "PHP $b (apk php$nn)"
  done
}

discover_pacman() {
  local p pkgs
  ALL_PKGS=$(pacman -Qq 2>/dev/null)
  for p in php php-legacy; do
    printf '%s\n' "$ALL_PKGS" | grep -qx "$p" || continue
    if [ "$p" = php ]; then
      pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E '^php(-|$)' | grep -v '^php-legacy' | tr '\n' ' ')
    else
      pkgs=$(printf '%s\n' "$ALL_PKGS" | grep -E '^php-legacy(-|$)' | tr '\n' ' ')
    fi
    add_install pacman pacman "" "/usr/bin/$p" "$pkgs" "$p" "PHP ($p, pacman)"
  done
}

discover_brew() {
  local f b
  for f in $(brew_cmd list --formula -1 2>/dev/null | grep -E '^php(@[0-9]+\.[0-9]+)?$'); do
    b=""; [ "$f" != php ] && b="${f#php@}"
    add_install brew brew "$b" "$BREW_PREFIX/opt/$f/bin/php" "$f" "$f" "Homebrew $f"
  done
}

manual_candidates() {
  local f
  for f in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
           /usr/local/bin/frankenphp /usr/bin/frankenphp \
           /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm /opt/php*/bin/php /opt/php*/sbin/php-fpm \
           /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/fcgi-bin/lsphp* \
           /opt/alt/php*/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php /opt/plesk/php/*/bin/php \
           /opt/remi/php*/root/usr/bin/php /opt/homebrew/bin/php* /opt/local/bin/php* \
           /Applications/MAMP/bin/php/php*/bin/php /Applications/XAMPP/xamppfiles/bin/php \
           "$UHOME/Library/Application Support/Herd/bin/"php* "$UHOME/.config/herd-lite/bin/"php* \
           "$UHOME/.phpbrew/php/"*/bin/php "$UHOME/.phpenv/versions/"*/bin/php; do
    [ -f "$f" ] && [ -x "$f" ] && printf '%s\n' "$f"
  done
}

pkg_owner() {
  case "$PM" in
    apt)            dpkg -S "$1" 2>/dev/null | grep -v '^diversion' | head -n1 | cut -d: -f1 | cut -d, -f1 ;;
    dnf|yum|zypper) rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -n1 ;;
    apk)            apk info -W "$1" 2>/dev/null | sed -n 's/.* is owned by \(.*\)-[0-9][^-]*-r[0-9]*$/\1/p' | head -n1 ;;
    pacman)         pacman -Qqo "$1" 2>/dev/null | head -n1 ;;
  esac
}

manual_label() {
  local pre
  pre=$(dirname "$(dirname "$1")")
  case "$1" in
    */lsws/*)                 echo "LiteSpeed ${pre##*/}" ;;
    /Applications/MAMP/*)     echo "MAMP ${pre##*/}" ;;
    /Applications/XAMPP/*)    echo "XAMPP PHP" ;;
    *Herd*|*herd-lite*)       echo "Laravel Herd PHP" ;;
    /opt/local/*)             echo "MacPorts ${1##*/}" ;;
    *frankenphp*)             echo "FrankenPHP $1" ;;
    */.phpbrew/*|*/.phpenv/*) echo "phpbrew/phpenv ${pre##*/}" ;;
    /usr/local/php[0-9]*)     echo "DirectAdmin $pre" ;;
    *)                        echo "Source build in $pre" ;;
  esac
}

discover_manual() {
  local f r base owner v fam key seen="|" prefixes="|"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    base=${f##*/}
    case "$base" in
      *config*|*ize*|*dbg*|*.ini) continue ;;
      php|php[0-9]*|php-fpm*|php-cgi*|lsphp*|frankenphp) ;;
      *) continue ;;
    esac
    r=$(resolve_path "$f")
    case "$KNOWN_BINS$seen" in *"|$r|"*) continue ;; esac
    seen="$seen$r|"
    if [ -n "$BREW_PREFIX" ]; then case "$r" in "$BREW_PREFIX"/*) continue ;; esac; fi
    owner=$(pkg_owner "$r")
    if [ -n "$owner" ]; then
      case "$KNOWN_PKGS" in *" $owner "*) continue ;; esac
      v=$(php_version "$r") || continue
      fam=$(printf '%s\n' "$ALL_PKGS" | grep -E "^$(esc_dots "$owner")(-|\$)" | tr '\n' ' ')
      [ -n "${fam// /}" ] || fam="$owner"
      add_install pkg "$PM" "$(branch_of "$v")" "$r" "$fam" "$owner" "$owner ($PM)"
    else
      v=$(php_version "$r") || continue
      key=$(dirname "$(dirname "$r")")
      case "$prefixes" in *"|$key|"*) continue ;; esac
      prefixes="$prefixes$key|"
      add_install manual none "$(branch_of "$v")" "$r" "" "" "$(manual_label "$r")"
    fi
  done <<EOF
$(manual_candidates)
EOF
}

docker_php_version() {
  run_t 20 docker exec "$1" sh -c 'for b in php php-fpm php-cgi frankenphp; do command -v $b >/dev/null 2>&1 || continue; if [ $b = frankenphp ]; then $b version; else $b -n -v; fi 2>/dev/null && break; done' 2>/dev/null \
    | sed -n 's/.*PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n1
}

discover_docker() {
  command -v docker >/dev/null 2>&1 || return 0
  local ids id name img v
  ids=$(run_t 10 docker ps -q 2>/dev/null) || return 0
  for id in $ids; do
    v=$(docker_php_version "$id")
    [ -n "$v" ] || continue
    name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    img=$(docker inspect -f '{{.Config.Image}}' "$id" 2>/dev/null)
    add_install docker none "$(branch_of "$v")" "docker:$id" "$img" "" "Docker: $name"
  done
}

discover() {
  case "$PM" in
    apt) discover_deb ;;
    dnf|yum|zypper) discover_rpm ;;
    apk) discover_apk ;;
    pacman) discover_pacman ;;
    brew) discover_brew ;;
  esac
  discover_manual
  [ "$DO_DOCKER" = 1 ] && discover_docker
  return 0
}

# ----------------------------------------------------------- evaluation --

# Number of distinct PHP2Shell CVE ids in the package changelog (0-2).
cve_hits() {
  local i=$1 c="${I_COMMON[$1]}" txt="" f
  case "${I_KIND[$i]}" in
    docker)
      txt=$(run_t 20 docker exec "${I_BIN[$i]#docker:}" sh -c 'for f in /usr/share/doc/php*-common/changelog.Debian.gz; do [ -f "$f" ] && gzip -dc "$f" | head -n 4000; done; command -v rpm >/dev/null 2>&1 && rpm -q --changelog php-common 2>/dev/null | head -n 4000' 2>/dev/null) ;;
    *)
      [ -n "$c" ] || { echo 0; return; }
      case "${I_PM[$i]}" in
        apt)
          for f in "/usr/share/doc/$c/changelog.Debian.gz" "/usr/share/doc/$c/changelog.gz"; do
            [ -f "$f" ] && txt="$txt$(gzip -dc "$f" 2>/dev/null | head -n 4000)"
          done
          # Minimal images strip /usr/share/doc; ask the archive instead.
          [ -z "$txt" ] && txt=$(run_t 30 apt-get changelog "$c" 2>/dev/null | head -n 4000) ;;
        dnf|yum|zypper)
          txt=$(rpm -q --changelog "$c" 2>/dev/null | head -n 4000) ;;
      esac ;;
  esac
  printf '%s\n' "$txt" | grep -oE 'CVE-2026-10961[89]' | sort -u | wc -l | tr -d ' '
}

# Sets I_AFTER / I_WHY. Returns 0 when the installation is safe.
evaluate() {
  local i=$1 v b fx hits
  if [ "${I_KIND[$i]}" = docker ]; then v=$(docker_php_version "${I_BIN[$i]#docker:}")
  else v=$(php_version "${I_BIN[$i]}"); fi
  I_AFTER[$i]="$v"
  if [ -z "$v" ]; then I_WHY[$i]="could not read its version"; return 2; fi
  b=$(branch_of "$v"); I_BRANCH[$i]="$b"
  fx=$(fixed_for "$b")
  if [ "$fx" = new ]; then I_WHY[$i]="released after the fix"; return 0; fi
  if [ -n "$fx" ] && ver_ge "$v" "$fx"; then I_WHY[$i]="$v ≥ $fx"; return 0; fi
  hits=$(cve_hits "$i")
  if [ "$hits" -ge 2 ]; then I_WHY[$i]="patched build, both CVEs in its changelog"; return 0; fi
  if [ "$hits" = 1 ]; then I_WHY[$i]="patched build, only one CVE in its changelog — verify"; return 0; fi
  if [ -z "$fx" ]; then I_WHY[$i]="end-of-life branch $b, no upstream fix"
  else I_WHY[$i]="needs $fx or a distro backport"; fi
  return 1
}

is_open() { case "${I_STATE[$1]}" in VULN|NEEDS) return 0 ;; esac; return 1; }

# Installations the package manager can act on.
open_managed() {
  local i=0
  while [ $i -lt $N ]; do
    if is_open $i; then
      case "${I_KIND[$i]}" in docker|manual) ;; *) echo $i ;; esac
    fi
    i=$((i + 1))
  done
}

count_open() {
  local i=0 n=0
  while [ $i -lt $N ]; do is_open $i && n=$((n + 1)); i=$((i + 1)); done
  echo $n
}

reevaluate() { # how
  local i
  for i in $(open_managed); do
    if evaluate "$i"; then I_STATE[$i]=FIXED; I_HOW[$i]="$1"; ok "${I_LABEL[$i]}: fixed — ${I_WHY[$i]}"; fi
  done
}

# ------------------------------------------------- tier 1: same repos --

REFRESHED=" "
pm_refresh() {
  case "$REFRESHED" in *" $1 "*) return 0 ;; esac
  REFRESHED="$REFRESHED$1 "
  case "$1" in
    apt)  run apt-get update -q -o DPkg::Lock::Timeout=300 || warn "apt-get update reported errors (continuing)" ;;
    apk)  run apk update -q || warn "apk update reported errors (continuing)" ;;
    brew) run brew_cmd update --quiet || warn "brew update reported errors (continuing)" ;;
  esac
}

APT_OPTS="-y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

pm_upgrade() { # pm pkgs...
  local pm="$1"; shift
  [ $# -gt 0 ] || return 0
  case "$pm" in
    apt)    pm_refresh apt
            # shellcheck disable=SC2086
            run env DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade $APT_OPTS "$@" ;;
    dnf)    run dnf -y upgrade --refresh "$@" ;;
    yum)    run yum -y update "$@" ;;
    zypper) run zypper --non-interactive --quiet refresh
            run zypper --non-interactive --quiet update "$@" ;;
    apk)    pm_refresh apk; run apk upgrade --no-progress "$@" ;;
    brew)   pm_refresh brew; run brew_cmd upgrade "$@" ;;
  esac
}

tier_packages() {
  local pm i list
  for pm in apt dnf yum zypper apk brew; do
    list=""
    for i in $(open_managed); do [ "${I_PM[$i]}" = "$pm" ] && list="$list ${I_PKGS[$i]}"; done
    [ -n "${list// /}" ] || continue
    # shellcheck disable=SC2046
    pm_upgrade "$pm" $(uniq_words $list) || warn "$pm reported an error (details in the log)"
  done
  for i in $(open_managed); do
    if [ "${I_PM[$i]}" = pacman ] && [ "$FORCE" != 1 ]; then
      needs $i "Arch does not support upgrading single packages. Run: pacman -Syu (or rerun with --force)"
    fi
  done
  [ "$DRY_RUN" = 1 ] || reevaluate "upgraded from your existing repositories"
}

# ------------------------------------------- tier 2: same-branch repos --

SURY_STATE=""   # "", present, added
SURY_PPA_KEY="14AA40EC0831756756D7F66C4F4EA0AAE5267A6C"
SURY_SRC=/etc/apt/sources.list.d/php2shell-sury.list
SURY_KEY=/etc/apt/keyrings/php2shell-sury.asc

sury_configured() {
  grep -rhsE '^[[:space:]]*(deb|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null \
    | grep -qE 'ppa\.launchpad(content)?\.net/ondrej/php|packages\.sury\.org/php'
}

add_sury() {
  [ "$SURY_STATE" = added ] && return 0
  if sury_configured; then SURY_STATE=present; return 0; fi
  local code url line tmp
  if is_ubuntu; then
    code="${UBU_CODENAME:-$OS_CODENAME}"
    url="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$SURY_PPA_KEY"
    line="deb [signed-by=$SURY_KEY] https://ppa.launchpadcontent.net/ondrej/php/ubuntu $code main"
    info "Adding Ondřej Surý's PPA (ppa:ondrej/php, $code)"
  else
    code="$OS_CODENAME"
    url="https://packages.sury.org/debsuryorg-archive-keyring.deb"
    line="deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $code main"
    info "Adding Ondřej Surý's repository (packages.sury.org/php, $code)"
  fi
  [ -n "$code" ] || { warn "Unknown release codename; cannot add Sury's repository"; return 1; }
  if [ "$DRY_RUN" = 1 ]; then
    printf '  %s[dry-run]%s write %s: %s\n' "$DIM" "$RST" "$SURY_SRC" "$line"
    SURY_STATE=added; return 0
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    pm_refresh apt
    # shellcheck disable=SC2086
    run env DEBIAN_FRONTEND=noninteractive apt-get install $APT_OPTS curl ca-certificates || return 1
  fi
  if is_ubuntu; then
    mkdir -p /etc/apt/keyrings
    if ! fetch "$url" "$SURY_KEY" || ! grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$SURY_KEY"; then
      warn "Could not download the PPA signing key"; rm -f "$SURY_KEY"; return 1
    fi
  else
    tmp=$(mktemp -d)
    if ! fetch "$url" "$tmp/sury.deb" || ! run dpkg -i "$tmp/sury.deb"; then
      warn "Could not install Sury's keyring"; rm -rf "$tmp"; return 1
    fi
    rm -rf "$tmp"
  fi
  echo "$line" >"$SURY_SRC"
  log "wrote $SURY_SRC: $line"
  if apt-get update -q -o DPkg::Lock::Timeout=300 2>&1 | tee -a "${LOG_FILE:-/dev/null}" \
       | grep -E 'sury|ondrej' | grep -qiE '^(E:|Err)|404|does not have a Release'; then
    warn "Sury's repository does not support $OS_NAME — removing it again"
    sury_cleanup; return 1
  fi
  REFRESHED="$REFRESHED""apt "
  SURY_STATE=added
}

sury_cleanup() {
  [ "$DRY_RUN" = 1 ] && return 0
  rm -f "$SURY_SRC" "$SURY_KEY"
  dpkg -s debsuryorg-archive-keyring >/dev/null 2>&1 && run dpkg -r debsuryorg-archive-keyring
  run apt-get update -q -o DPkg::Lock::Timeout=300
  SURY_STATE=""
}

REMI_STATE=""; EPEL_ADDED=0
add_remi() {
  [ -n "$REMI_STATE" ] && return 0
  if rpm -q remi-release >/dev/null 2>&1; then REMI_STATE=present; return 0; fi
  case "$EL" in 8|9) ;; *) warn "Remi's repository is only used on EL 8/9 here"; return 1 ;; esac
  if ! rpm -q epel-release >/dev/null 2>&1; then
    case "$OS_ID" in
      almalinux|rocky|centos) run dnf -y install epel-release ;;
      *) run dnf -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$EL.noarch.rpm" ;;
    esac || { warn "Could not install EPEL (Remi needs it)"; return 1; }
    EPEL_ADDED=1
  fi
  info "Adding Remi Collet's repository (rpms.remirepo.net, EL$EL)"
  run dnf -y install "https://rpms.remirepo.net/enterprise/remi-release-$EL.rpm" || { warn "Could not install remi-release"; return 1; }
  REMI_STATE=added
}

remi_cleanup() {
  [ "$REMI_STATE" = added ] || return 0
  run dnf -y remove remi-release
  [ "$EPEL_ADDED" = 1 ] && run dnf -y remove epel-release
  REMI_STATE=""; EPEL_ADDED=0
}

enable_crb() {
  case "$OS_ID" in
    rhel) command -v subscription-manager >/dev/null 2>&1 && \
            run subscription-manager repos --enable "codeready-builder-for-rhel-$EL-$(uname -m)-rpms" ;;
    ol)   run dnf config-manager --set-enabled "ol${EL}_codeready_builder" ;;
    *)    if [ "$EL" = 8 ]; then run dnf config-manager --set-enabled powertools
          else run dnf config-manager --set-enabled crb; fi ;;
  esac
}

dnf_stream_exists() { dnf -q module list php 2>/dev/null | awk '$1=="php"{print $2}' | grep -qx "$1"; }
dnf_enabled_stream() { dnf -q module list --enabled php 2>/dev/null | awk '$1=="php"{print $2; exit}'; }
rpm_php_names() { rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -E '^php(-|$)' | tr '\n' ' '; }

# Switch the php module stream and sync packages to it.
dnf_switch_stream() { # stream allow_erasing(0/1)
  local s="$1" erase="$2" names
  names=$(rpm_php_names)
  run dnf -y module reset php || return 1
  run dnf -y module enable "php:$s" || return 1
  # shellcheck disable=SC2086
  run dnf -y distro-sync $names && return 0
  enable_crb
  # shellcheck disable=SC2086
  run dnf -y distro-sync $names && return 0
  if [ "$erase" = 1 ]; then
    # shellcheck disable=SC2086
    run dnf -y distro-sync --allowerasing $names && return 0
  fi
  return 1
}

tier_repos() {
  local i list="" used=0 prev b
  case "$FAMILY" in
    debian)
      for i in $(open_managed); do [ "${I_KIND[$i]}" = deb ] && list="$list ${I_PKGS[$i]}"; done
      [ -n "${list// /}" ] || return 0
      add_sury || return 0
      [ "$SURY_STATE" = present ] && { info "Sury's repository is already configured — nothing more to add"; return 0; }
      # shellcheck disable=SC2046
      pm_upgrade apt $(uniq_words $list)
      [ "$DRY_RUN" = 1 ] && return 0
      for i in $(open_managed); do
        [ "${I_KIND[$i]}" = deb ] || continue
        if evaluate "$i"; then I_STATE[$i]=FIXED; I_HOW[$i]="same-branch build from Ondřej Surý"; used=1
          ok "${I_LABEL[$i]}: fixed — ${I_WHY[$i]}"; fi
      done
      if [ $used = 0 ]; then
        warn "Sury has no fixed build of this branch for $OS_NAME (it stops publishing for end-of-life releases) — removing the repository again"
        sury_cleanup
      fi
      ;;
    rhel)
      [ "$PM" = dnf ] || return 0
      case "$EL" in 8|9) ;; *) return 0 ;; esac
      for i in $(open_managed); do
        [ "${I_KIND[$i]}" = rpm ] || continue
        b="${I_BRANCH[$i]}"
        add_remi || return 0
        if [ "$DRY_RUN" != 1 ] && ! dnf_stream_exists "remi-$b"; then
          warn "Remi has no php:remi-$b stream"; continue
        fi
        prev=$(dnf_enabled_stream)
        info "Switching the php module from ${prev:-default} to Remi's build of the same branch (remi-$b)"
        if dnf_switch_stream "remi-$b" 0; then
          [ "$DRY_RUN" = 1 ] && continue
          if evaluate "$i"; then I_STATE[$i]=FIXED; I_HOW[$i]="same-branch build from Remi"; used=1
            ok "${I_LABEL[$i]}: fixed — ${I_WHY[$i]}"
            continue
          fi
        fi
        warn "Remi's build did not fix ${I_LABEL[$i]} — switching back to ${prev:-the default stream}"
        if [ -n "$prev" ]; then dnf_switch_stream "$prev" 0; else run dnf -y module reset php; fi
      done
      [ $used = 0 ] && remi_cleanup
      ;;
  esac
  return 0
}

# --------------------------------------------- PHPCompatibility scan --

pick_cli_php() {
  local i best="" bv="0" v
  i=0
  while [ $i -lt $N ]; do
    case "${I_KIND[$i]}" in docker) i=$((i + 1)); continue ;; esac
    case "${I_BIN[$i]##*/}" in php|php[0-9]*) ;; *) i=$((i + 1)); continue ;; esac
    v="${I_AFTER[$i]}"
    if [ -n "$v" ] && ver_ge "$v" 5.4 && [ "$(ver_cmp "$v" "$bv")" = 1 ]; then best="${I_BIN[$i]}"; bv="$v"; fi
    i=$((i + 1))
  done
  [ -z "$best" ] && best=$(command -v php 2>/dev/null)
  [ -n "$best" ] && echo "$best"
}

pm_install_tmp() { # pkg — install a helper package, remembering to remove it afterwards
  case "$PM" in
    apt)     pm_refresh apt
             # shellcheck disable=SC2086
             run env DEBIAN_FRONTEND=noninteractive apt-get install $APT_OPTS "$1" ;;
    dnf|yum) run "$PM" -y install "$1" ;;
    zypper)  run zypper --non-interactive install "$1" ;;
    apk)     run apk add --no-progress "$1" ;;
    pacman)  run pacman -S --noconfirm "$1" ;;
    *)       return 1 ;;
  esac && TMP_PKGS="$TMP_PKGS $1"
}
pm_remove_tmp() {
  local p
  for p in $TMP_PKGS; do
    case "$PM" in
      apt)     run env DEBIAN_FRONTEND=noninteractive apt-get remove -y -q "$p" ;;
      dnf|yum) run "$PM" -y remove "$p" ;;
      zypper)  run zypper --non-interactive remove "$p" ;;
      apk)     run apk del "$p" ;;
      pacman)  run pacman -R --noconfirm "$p" ;;
    esac
  done
  TMP_PKGS=""
}
TMP_PKGS=""

composer_req() { # php tmpdir [extra composer args]
  local php="$1" tmp="$2"; shift 2
  COMPOSER_HOME="$tmp/.composer" COMPOSER_ALLOW_SUPERUSER=1 "$php" "$tmp/composer.phar" --no-interaction --quiet \
    --working-dir="$tmp" "$@" require --dev "phpcompatibility/php-compatibility:^10.0@alpha || ^9.3" \
    "dealerdirect/phpcodesniffer-composer-installer:*" >>"${LOG_FILE:-/dev/null}" 2>&1
}

compat_scan() { # target branch
  local T="$1" php tmp url p rpt sum total name req
  php=$(pick_cli_php) || true
  if [ -z "$php" ]; then warn "No PHP CLI available to run the compatibility scan"; return 0; fi
  if ! command -v unzip >/dev/null 2>&1 && ! "$php" -m 2>/dev/null | grep -qix zip; then
    info "Installing unzip temporarily (Composer needs it for the scan)"
    pm_install_tmp unzip || { warn "Could not install unzip — skipping the scan"; return 0; }
  fi
  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t php2shell)
  info "Installing PHPCompatibility (temporary, removed afterwards)…"
  url=https://getcomposer.org/download/latest-stable/composer.phar
  ver_ge "$(php_version "$php")" 7.2.5 || url=https://getcomposer.org/download/latest-2.2.x/composer.phar
  if ! fetch "$url" "$tmp/composer.phar"; then
    warn "Could not download Composer — skipping the scan"; rm -rf "$tmp"; pm_remove_tmp; return 0
  fi
  printf '{"config":{"allow-plugins":{"dealerdirect/phpcodesniffer-composer-installer":true}}}\n' >"$tmp/composer.json"
  if ! composer_req "$php" "$tmp" && { ! command -v git >/dev/null 2>&1 || ! composer_req "$php" "$tmp" --prefer-source; }; then
    warn "Could not install PHPCompatibility — skipping the scan (details in the log)"; rm -rf "$tmp"; pm_remove_tmp; return 0
  fi
  for p in "${PROJECTS[@]}"; do
    [ -d "$p" ] || { warn "Project folder not found: $p"; continue; }
    name=$(basename "$(resolve_path "$p")")
    rpt="$RUN_DIR/compat-$name-php$T.txt"
    [ "$DRY_RUN" = 1 ] && rpt="$tmp/compat-$name.txt"
    info "Scanning $p for PHP $T problems (vendor/ and node_modules/ skipped)…"
    sum=$("$php" -d memory_limit=-1 "$tmp/vendor/bin/phpcs" -q --standard=PHPCompatibility \
          --runtime-set testVersion "$T" --extensions=php,inc,phtml,module \
          --ignore='*/vendor/*,*/node_modules/*,*/storage/*,*/cache/*' --parallel=4 \
          --report=summary --report-full="$rpt" "$p" 2>>"${LOG_FILE:-/dev/null}")
    total=$(printf '%s\n' "$sum" | grep 'A TOTAL OF' | sed 's/^[[:space:]]*//')
    if [ -z "$total" ]; then
      ok "$name: no PHP $T compatibility problems found"
    else
      if printf '%s' "$total" | grep -q ' [1-9][0-9]* ERROR'; then bad "$name: $total"; else warn "$name: $total"; fi
      printf '%s\n' "$sum" | grep -E '^/' | head -n 8 | sed 's/^/      /'
      [ "$DRY_RUN" = 1 ] || info "Full report: $rpt"
    fi
    if [ -f "$p/composer.json" ]; then
      req=$(sed -n 's/.*"php"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$p/composer.json" | head -n1)
      [ -n "$req" ] && info "$name/composer.json requires php \"$req\" — check it allows $T, then run composer update"
    fi
  done
  rm -rf "$tmp"
  pm_remove_tmp
}

# ----------------------------------------------- tier 3: --force --

RB=(); RB_N=0
rb_add() {
  RB[$RB_N]="$*"; RB_N=$((RB_N + 1))
  [ "$DRY_RUN" = 1 ] && return 0
  local k f="$RUN_DIR/rollback.sh"
  {
    echo '#!/usr/bin/env bash'
    echo "# Undo the --force changes of php2shell-fix run $RUN_ID (newest first)."
    echo 'set -x'
    k=$((RB_N - 1))
    while [ $k -ge 0 ]; do echo "${RB[$k]}"; k=$((k - 1)); done
  } >"$f"
  chmod 700 "$f"
}

svc_stop_disable() {
  if has_systemd; then run systemctl disable --now "$1"
  elif command -v rc-service >/dev/null 2>&1; then run rc-service "$1" stop; run rc-update del "$1" default
  elif command -v service >/dev/null 2>&1; then run service "$1" stop
  fi
}
svc_start_enable() {
  if has_systemd; then run systemctl enable "$1" && run systemctl restart "$1"
  elif command -v rc-service >/dev/null 2>&1; then run rc-update add "$1" default; run rc-service "$1" restart
  elif command -v service >/dev/null 2>&1; then run service "$1" restart
  else return 1; fi
}

INI_KEYS="memory_limit upload_max_filesize post_max_size max_execution_time max_input_time
max_input_vars max_file_uploads date.timezone display_errors log_errors error_log short_open_tag
session.gc_maxlifetime session.save_handler session.save_path default_charset expose_php
allow_url_fopen disable_functions open_basedir output_buffering realpath_cache_size
opcache.enable opcache.memory_consumption opcache.max_accelerated_files
opcache.revalidate_freq opcache.validate_timestamps"

# Carry common php.ini settings into a drop-in for the new branch.
migrate_ini() { # old_php.ini new_dropin
  local old="$1" dst="$2" k line out=""
  [ -f "$old" ] && [ -d "$(dirname "$dst")" ] || return 0
  [ -e "$dst" ] && return 0
  for k in $INI_KEYS; do
    line=$(grep -E "^[[:space:]]*$(esc_dots "$k")[[:space:]]*=" "$old" 2>/dev/null | tail -n1)
    [ -n "$line" ] && out="$out$line
"
  done
  [ -n "$out" ] || return 0
  [ "$DRY_RUN" = 1 ] && { info "Would carry php.ini settings into $dst"; return 0; }
  { echo "; Carried over from $old by $MARKER ($RUN_ID)"; printf '%s' "$out"; } >"$dst"
  info "Carried your php.ini settings into $dst"
  rb_add "rm -f '$dst'"
}

# Copy FPM pools to the new branch, renaming pool sections so they cannot
# clash. Pools keep their old listen sockets, so web server configs keep working.
copy_pools() { # src_dir dst_dir tag
  local f n
  for f in "$1"/*.conf; do
    [ -f "$f" ] || continue
    n="$2/from-$3-${f##*/}"
    [ "$DRY_RUN" = 1 ] && { info "Would copy pool ${f##*/} to $n"; continue; }
    sed "s/^[[:space:]]*\[\([^]]*\)\][[:space:]]*\$/[\1-$3]/" "$f" >"$n"
    rb_add "rm -f '$n'"
  done
}

warn_hardcoded_refs() { # pattern label
  local refs
  refs=$(grep -rlsE "$1" /etc/crontab /etc/cron.d /var/spool/cron /etc/supervisor /etc/supervisord.d /etc/systemd/system 2>/dev/null | tr '\n' ' ')
  [ -n "$refs" ] && warn "These still call $2 directly — update them: $refs"
}

apt_has() { apt-cache policy "$1" 2>/dev/null | grep -q 'Candidate: [^(]'; }

force_deb() {
  local i=$1 b="${I_BRANCH[$1]}" T pk ext cand newpkgs="" missing="" has_fpm=0 has_mod=0 sapi f nv prev_cli
  T=$(target_for "$b")
  [ -n "$T" ] || { needs $i "No newer supported branch to move to"; return 1; }
  [ -d "/etc/php/$b" ] || { needs $i "Unusual layout (no /etc/php/$b) — move to PHP $T by hand"; return 1; }
  info "${I_LABEL[$i]} → PHP $T"
  pm_refresh apt
  if ! apt_has "php$T-common"; then
    add_sury
    [ "$DRY_RUN" = 1 ] || apt_has "php$T-common" || { needs $i "PHP $T packages are not available for $OS_NAME"; return 1; }
  fi
  for pk in ${I_PKGS[$i]}; do
    case "$pk" in
      "libapache2-mod-php$b") has_mod=1; cand="libapache2-mod-php$T"; ext="apache module" ;;
      "php$b-"*) ext="${pk#php$b-}"
                 [ "$ext" = fpm ] && has_fpm=1
                 [ "$ext" = json ] && continue
                 cand="php$T-$ext" ;;
      *) continue ;;
    esac
    if [ "$DRY_RUN" = 1 ] || apt_has "$cand"; then newpkgs="$newpkgs $cand"; else missing="$missing $ext"; fi
  done
  [ -n "$missing" ] && warn "No PHP $T package for:$missing (built in, renamed or dropped — check your app)"
  [ "$DRY_RUN" = 1 ] || tar -czf "$RUN_DIR/etc-php-$b.tgz" -C / "etc/php/$b" 2>/dev/null
  prev_cli=$(resolve_path /etc/alternatives/php 2>/dev/null)
  # shellcheck disable=SC2086
  run env DEBIAN_FRONTEND=noninteractive apt-get install $APT_OPTS $newpkgs || { needs $i "apt could not install PHP $T"; return 1; }

  for sapi in fpm apache2 cgi cli; do
    migrate_ini "/etc/php/$b/$sapi/php.ini" "/etc/php/$T/$sapi/conf.d/98-$MARKER-from-$b.ini"
    for f in /etc/php/"$b"/"$sapi"/conf.d/*.ini; do
      [ -f "$f" ] && [ ! -L "$f" ] && [ -d "/etc/php/$T/$sapi/conf.d" ] || continue
      case "${f##*/}" in "$MITIG_NAME"|98-"$MARKER"*) continue ;; esac
      [ -e "/etc/php/$T/$sapi/conf.d/${f##*/}" ] && continue
      run cp -p "$f" "/etc/php/$T/$sapi/conf.d/" && rb_add "rm -f '/etc/php/$T/$sapi/conf.d/${f##*/}'"
    done
  done

  if [ $has_fpm = 1 ] && [ -d "/etc/php/$b/fpm/pool.d" ]; then
    copy_pools "/etc/php/$b/fpm/pool.d" "/etc/php/$T/fpm/pool.d" "php$b"
    if [ "$DRY_RUN" != 1 ] && ! "/usr/sbin/php-fpm$T" -t >>"${LOG_FILE:-/dev/null}" 2>&1; then
      rm -f "/etc/php/$T/fpm/pool.d/from-php$b-"*.conf
      needs $i "PHP $T FPM rejected the copied pools (see log) — nothing switched"; return 1
    fi
    svc_stop_disable "php$b-fpm"
    if svc_start_enable "php$T-fpm"; then
      ok "PHP-FPM $T now serves your php$b pools on the same sockets"
      rb_add "systemctl enable --now php$b-fpm 2>/dev/null || service php$b-fpm start"
      rb_add "rm -f /etc/php/$T/fpm/pool.d/from-php$b-*.conf; systemctl restart php$T-fpm 2>/dev/null || service php$T-fpm restart"
    else
      rm -f "/etc/php/$T/fpm/pool.d/from-php$b-"*.conf
      svc_start_enable "php$b-fpm"
      needs $i "PHP-FPM $T failed to start — switched back to $b"; return 1
    fi
  fi

  if [ $has_mod = 1 ] && [ -e "/etc/apache2/mods-enabled/php$b.load" ]; then
    run a2dismod -q "php$b"; run a2enmod -q "php$T"
    if [ "$DRY_RUN" = 1 ] || apache2ctl -t >>"${LOG_FILE:-/dev/null}" 2>&1; then
      ok "Apache now loads mod_php $T"
      rb_add "a2dismod -q php$T; a2enmod -q php$b; systemctl restart apache2"
    else
      run a2dismod -q "php$T"; run a2enmod -q "php$b"
      needs $i "Apache config test failed with mod_php $T — switched back"; return 1
    fi
  fi

  if [ -x "/usr/bin/php$T" ] || [ "$DRY_RUN" = 1 ]; then
    if [ "$(resolve_path /etc/alternatives/php 2>/dev/null)" = "/usr/bin/php$b" ]; then
      run update-alternatives --set php "/usr/bin/php$T"
    fi
    [ "$prev_cli" = "/usr/bin/php$b" ] && rb_add "update-alternatives --set php /usr/bin/php$b"
  fi
  warn_hardcoded_refs "php$(esc_dots "$b")([^0-9.]|\$)" "php$b"

  [ "$DRY_RUN" = 1 ] && return 0
  I_STATE[$i]=FORCED; I_HOW[$i]="moved to PHP $T"
  I_NOTE[$i]="PHP $b is still installed but no longer serving. Remove it when happy: apt purge 'php$b*'"
  NEED_RESTART=1
  add_install deb apt "$T" "/usr/bin/php$T" "$(uniq_words $newpkgs)" "php$T-common" "PHP $T (apt, new)"
  nv=$((N - 1))
  if evaluate $nv; then I_STATE[$nv]=FIXED; I_HOW[$nv]="installed by --force"
  else I_STATE[$nv]=VULN; fi
  I_BEFORE[$nv]="-"
}

force_rpm() {
  local i=$1 b="${I_BRANCH[$1]}" T prev s=""
  if [ "$PM" != dnf ] || { [ "$EL" != 8 ] && [ "$EL" != 9 ]; }; then
    needs $i "--force here supports EL8/EL9 module streams only"; return 1
  fi
  T=$(target_for "$b"); [ -n "$T" ] || { needs $i "No newer supported branch"; return 1; }
  prev=$(dnf_enabled_stream)
  if dnf_stream_exists "$T"; then s="$T"
  else add_remi && { [ "$DRY_RUN" = 1 ] || dnf_stream_exists "remi-$T"; } && s="remi-$T"; fi
  [ -n "$s" ] || { needs $i "No php:$T module stream available"; return 1; }
  info "${I_LABEL[$i]} → php:$s"
  [ "$DRY_RUN" = 1 ] || {
    tar -czf "$RUN_DIR/etc-php.tgz" -C / etc/php.ini etc/php.d etc/php-fpm.conf etc/php-fpm.d 2>/dev/null
    rpm -qa 'php*' | sort >"$RUN_DIR/rpm-php-before.txt"
  }
  if ! dnf_switch_stream "$s" 1; then
    warn "Switch failed — returning to php:${prev:-default}"
    if [ -n "$prev" ]; then dnf_switch_stream "$prev" 1; else run dnf -y module reset php; fi
    needs $i "dnf could not switch to php:$s (see log)"; return 1
  fi
  [ "$DRY_RUN" = 1 ] && return 0
  rb_add "dnf -y module reset php && dnf -y module enable php:${prev:-$b} && dnf -y distro-sync --allowerasing \$(rpm -qa --qf '%{NAME}\n' | grep -E '^php(-|\$)')"
  rpm -qa 'php*' | sort >"$RUN_DIR/rpm-php-after.txt"
  [ -f /etc/php.ini.rpmnew ] && warn "Kept your /etc/php.ini; PHP $T's default is /etc/php.ini.rpmnew — review it"
  warn_hardcoded_refs "php${b//./}" "php$b"
  I_HOW[$i]="moved from $b to php:$s"
  NEED_RESTART=1
  if evaluate "$i"; then I_STATE[$i]=FIXED; else I_STATE[$i]=VULN; fi
}

force_apk() {
  local i=$1 b="${I_BRANCH[$1]}" nn T tt pk ext cand newpkgs="" missing="" has_fpm=0 nv
  nn="${b//./}"; T=$(target_for "$b"); tt="${T//./}"
  [ -n "$T" ] || { needs $i "No newer supported branch"; return 1; }
  pm_refresh apk
  apk search -qx "php$tt" 2>/dev/null | grep -q . || { needs $i "Alpine $OS_VER has no php$tt package — upgrade Alpine or use a newer php image"; return 1; }
  for pk in ${I_PKGS[$i]}; do
    case "$pk" in
      "php$nn") cand="php$tt" ;;
      "php$nn-"*) ext="${pk#php$nn-}"; [ "$ext" = fpm ] && has_fpm=1
                  [ "$ext" = apache2 ] && { needs $i "Apache mod_php on Alpine must be switched by hand"; return 1; }
                  [ "$ext" = json ] && continue
                  cand="php$tt-$ext" ;;
      *) continue ;;
    esac
    if apk search -qx "$cand" 2>/dev/null | grep -q .; then newpkgs="$newpkgs $cand"; else missing="$missing $ext"; fi
  done
  [ -n "$missing" ] && warn "No php$tt package for:$missing"
  info "${I_LABEL[$i]} → php$tt"
  # shellcheck disable=SC2086
  run apk add --no-progress $newpkgs || { needs $i "apk could not install php$tt"; return 1; }
  migrate_ini "/etc/php$nn/php.ini" "/etc/php$tt/conf.d/98-$MARKER-from-$b.ini"
  if [ $has_fpm = 1 ] && [ -d "/etc/php$nn/php-fpm.d" ]; then
    copy_pools "/etc/php$nn/php-fpm.d" "/etc/php$tt/php-fpm.d" "php$nn"
    svc_stop_disable "php-fpm$nn"
    if svc_start_enable "php-fpm$tt"; then
      ok "php-fpm$tt now serves your php$nn pools"
      rb_add "rc-update add php-fpm$nn default; rc-service php-fpm$nn start"
      rb_add "rc-service php-fpm$tt stop; rm -f /etc/php$tt/php-fpm.d/from-php$nn-*.conf"
    else
      warn "Could not start php-fpm$tt (no init system?) — start it yourself"
    fi
  fi
  if [ -L /usr/bin/php ] && [ "$(resolve_path /usr/bin/php)" = "/usr/bin/php$nn" ] && [ -x "/usr/bin/php$tt" ]; then
    run ln -sf "php$tt" /usr/bin/php && rb_add "ln -sf php$nn /usr/bin/php"
  fi
  [ "$DRY_RUN" = 1 ] && return 0
  I_STATE[$i]=FORCED; I_HOW[$i]="moved to PHP $T"
  I_NOTE[$i]="php$nn is still installed but no longer serving. Remove it when happy: apk del 'php$nn*'"
  NEED_RESTART=1
  add_install apk apk "$T" "/usr/bin/php$tt" "$(uniq_words $newpkgs)" "php$tt" "PHP $T (apk php$tt, new)"
  nv=$((N - 1))
  if evaluate $nv; then I_STATE[$nv]=FIXED; I_HOW[$nv]="installed by --force"; else I_STATE[$nv]=VULN; fi
  I_BEFORE[$nv]="-"
}

force_brew() {
  local i=$1 f="${I_PKGS[$1]}" b="${I_BRANCH[$1]}" T nf cur running=0 nv
  T=$(target_for "$b"); [ -n "$T" ] || { needs $i "No newer supported branch"; return 1; }
  cur=$(brew_cmd info php 2>/dev/null | sed -n 's/.*stable \([0-9][0-9]*\.[0-9][0-9]*\)\..*/\1/p' | head -n1)
  nf="php@$T"; [ "$cur" = "$T" ] && nf=php
  info "$f → $nf"
  run brew_cmd install "$nf" || { needs $i "brew could not install $nf"; return 1; }
  if command -v valet >/dev/null 2>&1; then
    run valet use "$nf" --force && rb_add "valet use $f --force"
  else
    brew_cmd services list 2>/dev/null | awk -v f="$f" '$1==f && $2=="started"{found=1} END{exit !found}' && running=1
    [ $running = 1 ] && run brew_cmd services stop "$f"
    run brew_cmd unlink "$f"
    run brew_cmd link --overwrite --force "$nf"
    [ $running = 1 ] && run brew_cmd services start "$nf"
    rb_add "brew unlink $nf; brew link --overwrite --force $f$( [ $running = 1 ] && echo "; brew services stop $nf; brew services start $f")"
  fi
  [ "$DRY_RUN" = 1 ] && return 0
  warn "PECL extensions installed for $f must be reinstalled for $nf (pecl install …)"
  I_STATE[$i]=FORCED; I_HOW[$i]="moved to $nf"
  I_NOTE[$i]="$f is still installed but unlinked. Remove when happy: brew uninstall $f"
  add_install brew brew "$T" "$BREW_PREFIX/opt/$nf/bin/php" "$nf" "$nf" "Homebrew $nf (new)"
  nv=$((N - 1))
  if evaluate $nv; then I_STATE[$nv]=FIXED; I_HOW[$nv]="installed by --force"; else I_STATE[$nv]=VULN; fi
  I_BEFORE[$nv]="-"
}

countdown() {
  [ "$ASSUME_YES" = 1 ] || [ "$DRY_RUN" = 1 ] && return 0
  ( : >/dev/tty ) 2>/dev/null || return 0
  local s=10
  printf '\n  %s--force will switch PHP branches. Old apps can break.%s\n' "$YEL$B" "$RST" >/dev/tty
  while [ $s -gt 0 ]; do
    printf '\r  Continuing in %2ss — press Ctrl+C to abort ' "$s" >/dev/tty
    sleep 1; s=$((s - 1))
  done
  printf '\r%60s\r' '' >/dev/tty
}

tier_force() {
  local i
  for i in $(open_managed); do
    case "${I_KIND[$i]}" in
      deb)    if [ "${I_COMMON[$i]}" = php5-common ]; then
                needs $i "PHP 5 on an end-of-life distro — upgrade the OS first"
              else force_deb "$i"; fi ;;
      rpm)    force_rpm "$i" ;;
      apk)    force_apk "$i" ;;
      brew)   force_brew "$i" ;;
      pacman) run pacman -Syu --noconfirm
              [ "$DRY_RUN" = 1 ] || { evaluate "$i" && { I_STATE[$i]=FIXED; I_HOW[$i]="pacman -Syu"; }; } ;;
      *)      : ;;   # panels, SCL, vendor packages: see the hints in the summary
    esac
  done
}

# ---------------------------------------- tier 4: temporary mitigation --

ini_scan_dirs() {
  local bin="${I_BIN[$1]}" out d parent s
  case "${I_KIND[$1]}" in docker) return 0 ;; esac
  [ -x "$bin" ] || return 0
  out=$(run_t 15 "$bin" --ini 2>/dev/null | sed -n 's/^Scan for additional .ini files in:[[:space:]]*//p' | head -n1)
  case "$out" in ""|"(none)") return 0 ;; esac
  printf '%s\n' "$out" | tr ':' '\n' | while IFS= read -r d; do
    [ -n "$d" ] || continue
    case "$d" in
      /etc/php/*/*/conf.d)
        parent="${d%/*/conf.d}"
        for s in "$parent"/*/conf.d; do [ -d "$s" ] && echo "$s"; done ;;
      *) echo "$d" ;;
    esac
  done | sort -u
}

mitigate() { # idx
  local i=$1 d f wrote=0 dirs
  dirs=$(ini_scan_dirs "$i")
  if [ -z "$dirs" ]; then
    I_NOTE[$i]="${I_NOTE[$i]:+${I_NOTE[$i]} }No ini scan dir found: add session.upload_progress.enabled = 0 to its php.ini by hand."
    return 0
  fi
  while IFS= read -r d; do
    [ -d "$d" ] || continue
    f="$d/$MITIG_NAME"
    grep -qs "$MARKER" "$f" && { wrote=1; continue; }
    if [ "$DRY_RUN" = 1 ]; then info "Would write $f"; continue; fi
    {
      echo "; $MARKER temporary mitigation ($RUN_ID)"
      echo "; Blocks the session upload-progress path used by public exploits for $CVE_B."
      echo "; NOT a complete fix. Upgrade PHP, then delete this file (or rerun php2shell-fix.sh)."
      echo "session.upload_progress.enabled = 0"
    } >"$f" 2>/dev/null && { wrote=1; NEED_RESTART=1; log "wrote $f"; }
  done <<EOF
$dirs
EOF
  if [ $wrote = 1 ] && [ "$DRY_RUN" != 1 ]; then
    I_MITIG[$i]=1; MITIG_COUNT=$((MITIG_COUNT + 1))
    warn "${I_LABEL[$i]}: added session.upload_progress.enabled = 0 in $(printf '%s\n' "$dirs" | wc -l | tr -d ' ') ini folder(s) — partial protection only"
  fi
}

unmitigate() { # idx: remove our file once the install is fixed
  local i=$1 d f
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    f="$d/$MITIG_NAME"
    if grep -qs "$MARKER" "$f"; then
      run rm -f "$f" && { NEED_RESTART=1; info "Removed the old temporary mitigation $f"; }
    fi
  done <<EOF
$(ini_scan_dirs "$i")
EOF
}

tier_mitigate() {
  local i=0
  while [ $i -lt $N ]; do
    case "${I_STATE[$i]}" in
      VULN|NEEDS|FORCED) [ "${I_KIND[$i]}" != docker ] && [ "$DO_MITIGATE" = 1 ] && mitigate $i ;;
      OK|FIXED) unmitigate $i ;;
    esac
    i=$((i + 1))
  done
}

# ------------------------------------------------------------ restarts --

NEED_RESTART=0
MITIG_COUNT=0
SVC_RE='^(php[0-9.]*-fpm[0-9.]*|php-fpm[0-9.]*|php[0-9]+-php-fpm|ea-php[0-9]+-php-fpm|plesk-php[0-9]+-fpm|apache2|httpd|lsws|lshttpd|litespeed|openlitespeed|frankenphp|unit)$'

stale_processes() { # "pid name" of processes still running a replaced PHP binary or library
  [ -d /proc/self ] || return 0
  local p exe
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in *php*|*httpd*|*apache2*|*litespeed*|*unitd*) ;; *) continue ;; esac
    case "$exe" in
      *" (deleted)") ;;
      *) grep -qE '(libphp|/php).*\(deleted\)' "$p/maps" 2>/dev/null || continue ;;
    esac
    echo "${p#/proc/} $(cat "$p/comm" 2>/dev/null)"
  done
}

restart_linux() {
  local units u n
  if has_systemd; then
    units=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
            | awk '{print $1}' | sed 's/\.service$//' | grep -E "$SVC_RE")
    if [ -x /scripts/restartsrv_apache_php_fpm ]; then
      run /scripts/restartsrv_apache_php_fpm && ok "Restarted cPanel PHP-FPM"
      units=$(printf '%s\n' "$units" | grep -v '^ea-php')
    fi
    # PHP-FPM first, web servers after.
    for u in $(printf '%s\n' "$units" | grep -E 'php|fpm') $(printf '%s\n' "$units" | grep -vE 'php|fpm'); do
      if run systemctl restart "$u"; then ok "Restarted $u"; else bad "Could not restart $u — check: systemctl status $u"; fi
    done
    [ -z "$units" ] && info "No running PHP or web server services found"
  elif command -v rc-service >/dev/null 2>&1; then
    for u in /etc/init.d/*; do
      n=${u##*/}; printf '%s\n' "$n" | grep -qE "$SVC_RE" || continue
      rc-service "$n" status >/dev/null 2>&1 || continue
      if run rc-service "$n" restart; then ok "Restarted $n"; else bad "Could not restart $n"; fi
    done
  elif command -v service >/dev/null 2>&1; then
    for u in /etc/init.d/*; do
      n=${u##*/}; printf '%s\n' "$n" | grep -qE "$SVC_RE" || continue
      service "$n" status >/dev/null 2>&1 || continue
      if run service "$n" restart; then ok "Restarted $n"; else bad "Could not restart $n"; fi
    done
  else
    warn "No service manager found — restart PHP and your web server yourself"
  fi
  if [ -x /usr/local/lsws/bin/lswsctrl ]; then
    run /usr/local/lsws/bin/lswsctrl restart && ok "Restarted LiteSpeed"
    if stale_processes | grep -q lsphp; then run pkill -f '/lsphp'; fi
  fi
}

restart_mac() {
  local f
  [ -n "$BREW_BIN" ] || return 0
  for f in $(brew_cmd services list 2>/dev/null | awk '$1 ~ /^php(@[0-9.]+)?$/ && $2=="started"{print $1}'); do
    if run brew_cmd services restart "$f"; then ok "Restarted $f"; else bad "Could not restart $f"; fi
  done
  command -v valet >/dev/null 2>&1 && [ "$NEED_RESTART" = 1 ] && run valet restart
  return 0
}

STALE_LEFT=""
tier_restart() {
  local stale
  if [ "$OS" = mac ]; then
    if [ "$DO_RESTART" = 1 ] && [ "$NEED_RESTART" = 1 ]; then restart_mac
    elif [ "$NEED_RESTART" = 1 ]; then warn "Restart PHP yourself (brew services restart php…)"; fi
    return 0
  fi
  stale=$(stale_processes)
  if [ -z "$stale" ] && [ "$NEED_RESTART" = 0 ]; then
    ok "No PHP process is running an outdated binary — no restart needed"; return 0
  fi
  if [ "$DO_RESTART" = 0 ]; then
    warn "Restart PHP-FPM and your web server — they still run the old code ($(printf '%s\n' "$stale" | awk '{print $2}' | sort -u | tr '\n' ' '))"
    STALE_LEFT="$stale"; return 0
  fi
  [ "$DRY_RUN" = 1 ] && { info "Would restart PHP-FPM and web servers"; return 0; }
  restart_linux
  sleep 2
  STALE_LEFT=$(stale_processes)
  if [ -n "$STALE_LEFT" ]; then
    warn "Still running old PHP code: $(printf '%s\n' "$STALE_LEFT" | awk '{print $2"("$1")"}' | tr '\n' ' ')"
  else
    ok "No PHP process is running an outdated binary"
  fi
}

# ----------------------------------------------------------- reporting --

# Where a patched build of the SAME end-of-life branch can still come from,
# when no free repository has one for this OS.
lts_option() {
  case "$OS_ID:${UBU_CODENAME:-$OS_CODENAME}" in
    ubuntu:xenial|ubuntu:bionic|ubuntu:focal|ubuntu:trusty)
      if command -v pro >/dev/null 2>&1 && pro status 2>/dev/null | grep -qE '^esm-(apps|infra)[[:space:]]+yes[[:space:]]+enabled'; then
        echo "Ubuntu Pro is attached but has no fix yet — rerun later to stay on this version."
      else
        echo "Stay on this version: Ubuntu Pro has a patched build and is free for up to 5 machines (ubuntu.com/pro). Run: sudo pro attach <token>, then rerun this script."
      fi ;;
    debian:stretch|debian:buster|debian:bullseye)
      echo "Stay on this version: Freexian ELTS (paid, freexian.com) publishes patched PHP for Debian $OS_VER; add its repo, then rerun this script." ;;
    *)
      echo "Stay on this version: paid extended support (TuxCare ELS for PHP, or Zend PHP LTS) patches end-of-life branches." ;;
  esac
}

hint_for() {
  local i=$1 b="${I_BRANCH[$1]}" fx t
  fx=$(fixed_for "$b"); t=$(target_for "$b")
  case "${I_KIND[$i]}" in
    docker)  echo "Rebuild or pull ${I_PKGS[$i]} with PHP ${fx:-$t+} (or a distro-patched build), then recreate the container." ;;
    manual)
      if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
        echo "Inside a container: rebuild from a php:${t:-8.3} (or newer) base image instead of patching it."; return
      fi
      case "${I_LABEL[$i]}" in
        LiteSpeed*) echo "Update lsphp from LiteSpeed's repository, then restart LiteSpeed." ;;
        MAMP*)      echo "Update MAMP, or point your project at Homebrew PHP." ;;
        XAMPP*)     echo "Install a current XAMPP release." ;;
        Laravel\ Herd*) echo "Update PHP inside the Herd app." ;;
        MacPorts*)  echo "sudo port selfupdate && sudo port upgrade outdated" ;;
        FrankenPHP*) echo "Download a FrankenPHP release built on PHP ${fx:-$t+}." ;;
        DirectAdmin*) echo "DirectAdmin: cd /usr/local/directadmin/custombuild && ./build update && ./build php" ;;
        *)          if [ -n "$fx" ]; then echo "Rebuild from php-src $fx or newer, or replace it with packages."
                    else echo "EOL build: rebuild with the PHP security team's backport patch, or replace it with packages."; fi ;;
      esac ;;
    panel)
      case "${I_LABEL[$i]}" in
        cPanel*)     echo "WHM ▸ EasyApache 4 update; for EOL builds switch sites to ea-php${t//./}+ in MultiPHP Manager." ;;
        CloudLinux*) echo "yum update 'alt-php*' when CloudLinux publishes it; or switch sites to a newer alt-php." ;;
        Plesk*)      echo "Plesk ▸ Tools & Settings ▸ Updates; or switch sites to PHP $t+." ;;
      esac ;;
    rpm-scl) echo "dnf upgrade 'php${b//./}-*' once Remi publishes it, or move sites to a newer phpNN SCL." ;;
    pacman)  echo "pacman -Syu" ;;
    apk)     echo "Upgrade to a supported Alpine release (alpinelinux.org/releases) — end-of-life Alpine gets no PHP fixes." ;;
    pkg)     echo "Update ${I_COMMON[$i]} when its vendor publishes a fix." ;;
    *)
      if [ -n "$fx" ]; then echo "Your distro hasn't shipped the fix yet — rerun later, or use --force to move to $t."
      else echo "$(lts_option) Last resort: --force moves to PHP $t (add --project /path/to/app to check your code first)."; fi ;;
  esac
}

print_row() { # icon label before after text
  printf '  %s %-36.36s %-9.9s %-9.9s %s\n' "$1" "$2" "$3" "$4" "$5"
}

summary() {
  local i=0 icon text open=0 note
  step "Summary"
  printf '  %s  %-36s %-9s %-9s %s%s\n' "$B" "PHP installation" "Before" "Now" "Result" "$RST"
  while [ $i -lt $N ]; do
    note=""
    case "${I_STATE[$i]}" in
      OK)     icon="$GRN✓$RST"; text="already safe (${I_WHY[$i]})" ;;
      FIXED)  icon="$GRN✓$RST"; text="fixed: ${I_HOW[$i]} (${I_WHY[$i]})" ;;
      FORCED) icon="$GRN✓$RST"; text="${I_HOW[$i]}"; note="${I_NOTE[$i]}" ;;
      *)      open=$((open + 1))
              if [ "${I_MITIG[$i]}" = 1 ]; then icon="$YEL!$RST"; text="partly protected by temporary php.ini mitigation"
              elif [ "$DRY_RUN" = 1 ]; then icon="$RED✗$RST"; text="vulnerable (${I_WHY[$i]}) — plan shown above"
              else icon="$RED✗$RST"; text="still vulnerable (${I_WHY[$i]})"; fi
              note="${I_NOTE[$i]:-$(hint_for $i)}" ;;
    esac
    print_row "$icon" "${I_LABEL[$i]}" "${I_BEFORE[$i]:-?}" "${I_AFTER[$i]:-?}" "$text"
    [ -n "$note" ] && printf '      %s→ %s%s\n' "$DIM" "$note" "$RST"
    i=$((i + 1))
  done
  [ -n "$STALE_LEFT" ] && { open=$((open + 1)); bad "Some processes still run old PHP code — restart them."; }
  echo
  if [ "$DRY_RUN" = 1 ]; then
    info "Dry run — nothing was changed."
  elif [ $open -eq 0 ]; then
    printf '  %s%sAll PHP on this machine is protected from PHP2Shell.%s\n' "$B" "$GRN" "$RST"
  else
    printf '  %s%s%s item(s) still need attention — see the arrows above.%s\n' "$B" "$YEL" "$open" "$RST"
  fi
  [ -n "$LOG_FILE" ] && info "Log: $LOG_FILE"
  [ "$RB_N" -gt 0 ] && [ "$DRY_RUN" != 1 ] && info "Undo the --force changes with: sudo bash php2shell-fix.sh --rollback"
  return $open
}

print_found() {
  local i=0 icon
  while [ $i -lt $N ]; do
    if [ "${I_STATE[$i]}" = OK ]; then icon="$GRN✓$RST"; else icon="$RED✗$RST"; fi
    print_row "$icon" "${I_LABEL[$i]}" "${I_BEFORE[$i]:-?}" "" "${I_WHY[$i]}"
    i=$((i + 1))
  done
}

# ------------------------------------------------------------- rollback --

do_rollback() {
  local d f=""
  for d in $(ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort -r); do
    [ -f "$d/rollback.sh" ] && { f="$d/rollback.sh"; break; }
  done
  [ -n "$f" ] || die "No --force changes to roll back (looked in $BACKUP_ROOT)"
  step "Rolling back $(basename "$(dirname "$f")")"
  sed '1,3d' "$f" | sed 's/^/    /'
  ASSUME_YES=${ASSUME_YES:-0}; countdown
  if bash "$f" >>"${LOG_FILE:-/dev/null}" 2>&1; then ok "Rolled back"; else warn "Some rollback steps failed — see $LOG_FILE"; fi
  mv "$f" "$f.done"
  info "Restart PHP-FPM / your web server if they were running."
}

# ----------------------------------------------------------------- main --

main() {
  detect_os

  if [ "$OS" = linux ] && [ "$(id -u)" != 0 ]; then
    if [ "$DRY_RUN" = 1 ]; then
      :
    elif [ -f "$0" ] && command -v sudo >/dev/null 2>&1; then
      exec sudo bash "$0" "${ORIG_ARGS[@]}"
    else
      die "Run as root, e.g.:  curl -fsSL https://php2shell.wizeb.com/autofix | sudo bash"
    fi
  fi
  if [ "$OS" = mac ] && [ "$(id -u)" = 0 ] && [ -z "$BREW_USER" ] && [ -n "$BREW_BIN" ]; then
    die "On macOS, run without sudo (Homebrew refuses to run as root)"
  fi

  if [ -n "$TARGET" ]; then
    case " $SUPPORTED_BRANCHES " in *" $TARGET "*) ;; *) die "--target must be one of: $SUPPORTED_BRANCHES" ;; esac
  fi

  if [ "$OS" = mac ]; then
    BACKUP_ROOT="$UHOME/.php2shell-fix"; LOG_FILE="$UHOME/Library/Logs/php2shell-fix.log"
  else
    BACKUP_ROOT=/var/backups/php2shell-fix; LOG_FILE=/var/log/php2shell-fix.log
  fi
  RUN_ID=$(date +%Y%m%d-%H%M%S)
  RUN_DIR="$BACKUP_ROOT/$RUN_ID"
  if [ "$DRY_RUN" = 1 ]; then
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE=""
  else
    mkdir -p "$RUN_DIR" 2>/dev/null || die "Cannot create $RUN_DIR"
    chmod 700 "$BACKUP_ROOT" 2>/dev/null
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; touch "$LOG_FILE" 2>/dev/null || LOG_FILE=""
    LOCK="$BACKUP_ROOT/.lock"
    mkdir "$LOCK" 2>/dev/null || die "Another run is in progress (remove $LOCK if not)"
    trap 'rmdir "$LOCK" 2>/dev/null; rmdir "$RUN_DIR" 2>/dev/null' EXIT
    trap 'exit 130' INT TERM
  fi
  log "---- php2shell-fix $VERSION ($RUN_ID) on $OS_NAME, args: ${ORIG_ARGS[*]}"

  printf '%sphp2shell-fix %s%s — %s and %s — %s\n' "$B" "$VERSION" "$RST" "$CVE_A" "$CVE_B" "$OS_NAME"

  if [ "$ROLLBACK" = 1 ]; then do_rollback; exit 0; fi

  step "Looking for PHP"
  discover
  if [ $N -eq 0 ]; then ok "No PHP found on this machine."; exit 0; fi
  local i=0
  while [ $i -lt $N ]; do
    if evaluate $i; then I_STATE[$i]=OK; else I_STATE[$i]=VULN; fi
    I_BEFORE[$i]="${I_AFTER[$i]}"
    i=$((i + 1))
  done
  print_found

  if [ -n "$(open_managed)" ]; then
    step "Patching from your existing repositories"
    tier_packages
  fi
  if [ -n "$(open_managed)" ] && { [ "$FAMILY" = debian ] || [ "$FAMILY" = rhel ]; }; then
    step "Looking for a same-branch fix in a trusted repository"
    tier_repos
  fi

  if [ -n "$(open_managed)" ]; then
    local first t
    first=$(open_managed | head -n1); t=$(target_for "${I_BRANCH[$first]}")
    if [ ${#PROJECTS[@]} -gt 0 ] && [ -n "$t" ]; then
      step "Checking your code against PHP $t"
      compat_scan "$t"
    fi
    if [ "$FORCE" = 1 ]; then
      step "--force: moving to a supported PHP branch"
      countdown
      tier_force
    else
      if [ "$DRY_RUN" = 1 ]; then
        info "If the steps above don't fix it, only --force (moving branch) can"
      else
        info "$(open_managed | wc -l | tr -d ' ') installation(s) can only be fixed by moving branch: rerun with --force"
      fi
    fi
  elif [ ${#PROJECTS[@]} -gt 0 ]; then
    info "Everything was patched in place — no branch change, so the --project scan was skipped."
  fi

  if [ "$(count_open)" -gt 0 ] || [ "$DO_MITIGATE" = 1 ]; then
    step "Temporary mitigation for anything still vulnerable"
    tier_mitigate
    [ "$MITIG_COUNT" -eq 0 ] && ok "Nothing needed it"
  fi

  step "Restarting PHP"
  tier_restart

  summary
  [ $? -eq 0 ] && exit 0
  exit 1
}

main
