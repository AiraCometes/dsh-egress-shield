#!/usr/bin/env bash
# Read-only audit of a local DeepSeek Harness (DSH) installation.
#
# - Changes nothing: no installs, no config writes, no service restarts, no network.
# - Never prints credential values: .env and unit Environment= lines show key names only.
# - Output is passed through a redaction filter (home, user, hostname, tailnet names,
#   e-mail addresses, CGNAT addresses) so it can be pasted for review.
#
# Usage: bash scripts/audit-local.sh [> audit.txt]

set -u
export LC_ALL=C

DSH_HOME_DIR="${DSH_HOME:-$HOME/.dsh}"
ME="$(id -un 2>/dev/null || echo "${USER:-unknown}")"
HOST_SHORT="$(hostname -s 2>/dev/null || echo unknown-host)"

redact() {
  # Generic account names (root, user, ...) are not identifying and would mangle ordinary words.
  local user_expr="" host_expr=""
  case "$ME" in root|user|admin|ubuntu|"") ;; *) user_expr="s#\b${ME}\b#<user>#g" ;; esac
  case "$HOST_SHORT" in localhost|"") ;; *) host_expr="s#\b${HOST_SHORT}\b#<host>#g" ;; esac
  sed -E \
    -e "s#[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.ts\.net#<tailnet-host>#g" \
    -e "s#${HOME//#/\\#}#~#g" \
    -e "s#/mnt/[a-z]/Users/[^/ ]+#/mnt/<drive>/Users/<winuser>#g" \
    -e "s#[A-Za-z]:\\\\Users\\\\[^\\\\ ]+#<drive>:\\\\Users\\\\<winuser>#g" \
    ${user_expr:+-e "$user_expr"} \
    ${host_expr:+-e "$host_expr"} \
    -e "s#[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}#<email>#g" \
    -e "s#\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b#<tailscale-ip>#g" \
    -e "s#(sk|ghp|gho|github_pat|tskey|xox[a-z])[-_][A-Za-z0-9_-]{8,}#<token>#g"
}

section() { printf '\n## %s\n' "$1"; }

classify_url() {
  # Print scheme + host class for a URL, never path/query/userinfo.
  local url="$1" host
  host="$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://([^/@]*@)?([^/:?]+).*#\2#')"
  case "$host" in
    127.*|localhost|::1|\[::1\]) echo "loopback ($host)" ;;
    api.deepseek.com|opencode.ai|api.openai.com|api.anthropic.com|openrouter.ai|generativelanguage.googleapis.com) echo "remote ($host)" ;;
    *) echo "remote (<other-host>)" ;;
  esac
}

main() {
  echo "# DSH local audit ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

  section "Runtime"
  echo "kernel: $(uname -r)"
  grep -qi microsoft /proc/version 2>/dev/null && echo "wsl: yes" || echo "wsl: no"
  command -v node >/dev/null && echo "node: $(node -v)" || echo "node: not found"
  command -v npm  >/dev/null && echo "npm: $(npm -v 2>/dev/null)"
  echo "dsh binary: $(command -v dsh || echo 'not on PATH')"

  section "DSH package"
  local groot
  groot="$(npm root -g 2>/dev/null || true)"
  for pkg in dsh dsh-llm dsh-llm-pi-ai dsh-llm-deepseek dsh-session-log-deepseek dsh-http-proxy; do
    local pj="$groot/@deepseek-ai/$pkg/package.json"
    [ -f "$pj" ] || pj="$groot/@deepseek-ai/dsh/node_modules/@deepseek-ai/$pkg/package.json"
    if [ -f "$pj" ]; then
      echo "@deepseek-ai/$pkg: $(node -p "require('$pj').version" 2>/dev/null)"
    else
      echo "@deepseek-ai/$pkg: (not found under global npm root)"
    fi
  done
  local pi="$groot/@deepseek-ai/dsh/node_modules/@earendil-works/pi-ai/package.json"
  [ -f "$pi" ] && echo "@earendil-works/pi-ai: $(node -p "require('$pi').version")"
  local cordis="$groot/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis/package.json"
  [ -f "$cordis" ] && echo "@deepseek-ai/cordis: $(node -p "require('$cordis').version")"

  section "DSH_HOME layout"
  echo "DSH_HOME: $DSH_HOME_DIR (env set: $([ -n "${DSH_HOME:-}" ] && echo yes || echo no))"
  if [ -d "$DSH_HOME_DIR" ]; then
    echo "profiles: $(ls -1 "$DSH_HOME_DIR/profiles" 2>/dev/null | tr '\n' ' ')"
    echo "sessions dir present: $([ -d "$DSH_HOME_DIR/sessions" ] && echo yes || echo no)"
    if [ -f "$DSH_HOME_DIR/.env" ]; then
      echo ".env keys (values hidden): $(grep -Eo '^[A-Za-z_][A-Za-z0-9_]*=' "$DSH_HOME_DIR/.env" | tr -d '=' | tr '\n' ' ')"
      echo ".env mode: $(stat -c '%a' "$DSH_HOME_DIR/.env")"
    fi
  fi

  section "Profile patch layers (plugin rows and provider endpoints)"
  local f
  while IFS= read -r f; do
    echo "### $f"
    grep -nE "^\s*-?\s*(id|name):" "$f" | sed -E 's/^\s+//' | head -80
    grep -nE "enabled:\s*(true|false)" "$f" | head -20
    grep -nE "baseURL:" "$f" | while IFS= read -r line; do
      local url
      url="$(printf '%s' "$line" | sed -E "s/.*baseURL:\s*['\"]?([^'\" ]+).*/\1/")"
      echo "baseURL line ${line%%:*}: $(classify_url "$url")"
    done
  done < <(find "$DSH_HOME_DIR/profiles" -maxdepth 2 -name 'cordis.patch.yml' 2>/dev/null)

  section "Installed plugin packages under DSH_HOME"
  find "$DSH_HOME_DIR" -maxdepth 5 -path '*/node_modules/*' -name package.json 2>/dev/null \
    | grep -v '/node_modules/.*/node_modules/' | head -200 \
    | while IFS= read -r pj; do node -p "const p=require('$pj');p.name+'@'+p.version" 2>/dev/null; done | sort -u

  section "Environment variables relevant to egress (names and presence only)"
  for v in DEEPSEEK_BASE_URL DEEPSEEK_SEARCH_BASE_URL DSH_TELEMETRY_DISABLED DSH_TELEMETRY_MODE \
           DSH_TELEMETRY_OTLP_URL HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY OPENCODE_API_KEY DEEPSEEK_API_KEY; do
    if [ -n "${!v:-}" ]; then echo "$v: set"; else echo "$v: unset"; fi
  done
  echo "(this shell only; the service's environment is listed below)"

  section "systemd units mentioning dsh"
  for scope in "--user" ""; do
    systemctl $scope list-units --all --no-pager --plain 2>/dev/null | grep -iE 'dsh|deepseek|harness' \
      | while read -r unit _; do
          echo "### unit ($([ -n "$scope" ] && echo user || echo system)): $unit"
          systemctl $scope cat "$unit" --no-pager 2>/dev/null \
            | grep -E '^(ExecStart|User|WorkingDirectory|Restart|EnvironmentFile|Environment)=' \
            | while IFS= read -r l; do
                case "$l" in
                  Environment=*)
                    # key names only; values (even quoted ones with spaces) are never printed
                    echo "Environment keys: $(printf '%s' "${l#Environment=}" \
                      | grep -oE '(^|[ "])[A-Za-z_][A-Za-z0-9_]*=' | tr -d ' "=' | tr '\n' ' ')" ;;
                  *)
                    printf '%s\n' "$l" | sed -E 's/(--?[A-Za-z-]*(key|token|secret|password|passwd)[A-Za-z-]*[= ])[^ ]+/\1<hidden>/Ig' ;;
                esac
              done
          echo "active: $(systemctl $scope is-active "$unit" 2>/dev/null)"
        done
  done

  section "Listening sockets owned by node (loopback vs wildcard)"
  ss -ltnp 2>/dev/null | grep -i node | awk '{print $4}' | sed -E 's/:[0-9]+$/:<port>/' | sort | uniq -c
}

main 2>&1 | redact
