#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/go/bin:$PATH"
TS=$(date +"%Y%m%d-%H%M%S")
RUN_DIR="results/$TS"
mkdir -p "$RUN_DIR"

RATE_LIMIT=${RATE_LIMIT:-50}
INCLUDE_SEVERITY=${INCLUDE_SEVERITY:-low,medium,high}
DRY_RUN=${DRY_RUN:-false}

SCOPE_FILE="scripts/scope.txt"
OOS_FILE="scripts/out_of_scope.txt"
DENY_RE="scripts/denylist_regex.txt"
PORTS_FILE="scripts/allowed_ports.txt"

# 1) Resolve subdomains per root domain (passive-first)
: > tmp/subs_raw.txt
while read -r ROOT; do
  [[ -z "$ROOT" || "$ROOT" =~ ^# ]] && continue
  echo "[+] Subfinder: $ROOT" >&2
  subfinder -silent -all -recursive -d "$ROOT" \
    -sources crtsh,waybackarchive,urlscan,github,shodan,chaos,rapiddns,fofa,alienvault \
    | sed 's/\r//g' >> tmp/subs_raw.txt || true
  # Also include the apex itself
  echo "$ROOT" >> tmp/subs_raw.txt

done < "$SCOPE_FILE"

sort -u tmp/subs_raw.txt > tmp/subs_all.txt

# 2) Safety filters: out-of-scope and denylisted envs
if [[ -s "$OOS_FILE" ]]; then
  grep -v -f "$OOS_FILE" tmp/subs_all.txt > tmp/subs_scoped.txt || true
else
  cp tmp/subs_all.txt tmp/subs_scoped.txt
fi

if [[ -s "$DENY_RE" ]]; then
  # Drop obvious non-prod/dev hosts
  grep -Ev -f "$DENY_RE" tmp/subs_scoped.txt > tmp/subs_safe.txt || true
else
  cp tmp/subs_scoped.txt tmp/subs_safe.txt
fi

# 3) Alive check with ultra-conservative rates
httpx -silent -no-color -mc 200,301,302,401,403,405 \
  -follow-host-redirects \
  -threads 25 -rl "$RATE_LIMIT" \
  -retries 1 -random-agent \
  -probe -title -tech-detect \
  -list tmp/subs_safe.txt \
  -o "$RUN_DIR/httpx_live.txt"

# 4) Optional port scan (only whitelisted ports)
if [[ "$DRY_RUN" == "true" ]]; then
  echo "[+] DRY_RUN enabled: skipping naabu/nmap" >&2
else
  if [[ -s "$PORTS_FILE" ]]; then
    ALLOWED_PORTS=$(grep -E '^[0-9]+$' "$PORTS_FILE" | paste -sd, -)
  else
    ALLOWED_PORTS="80,443"
  fi
  echo "[+] Naabu on allowed ports: $ALLOWED_PORTS" >&2
  cut -d/ -f3 "$RUN_DIR/httpx_live.txt" | cut -d: -f1 | sed 's/^https\?:\/\///' | sort -u > tmp/hosts_alive.txt
  naabu -host -l tmp/hosts_alive.txt -p "$ALLOWED_PORTS" \
    -silent -json -rate 150 -retries 1 -warm-up-time 2 \
    -exclude-cdn -o "$RUN_DIR/naabu.json" || true

  # Light nmap service/version only on open ports reported by naabu
  if [[ -s "$RUN_DIR/naabu.json" ]]; then
    jq -r 'select(.port != null) | "\(.host):\(.port)"' "$RUN_DIR/naabu.json" | sort -u > tmp/targets_ports.txt
    if [[ -s tmp/targets_ports.txt ]]; then
      echo "[+] Nmap light scan" >&2
      nmap -sV -sT -Pn --version-light -T2 -oA "$RUN_DIR/nmap_light" -iL tmp/hosts_alive.txt -p "$ALLOWED_PORTS" || true
    fi
  fi
fi

# 5) Nuclei non-destructive scan
#    - Exclude destructive tags (dos,bruteforce,iot-takeover,rce-active,delete)
#    - Respect rate limit & no template that modifies state
NUCLEI_OUT="$RUN_DIR/nuclei_findings.jsonl"

httpx -silent -no-color -mc 200,301,302,401,403,405 \
  -follow-host-redirects -threads 25 -rl "$RATE_LIMIT" \
  -retries 1 -random-agent \
  -store-response \
  -list tmp/subs_safe.txt | tee "$RUN_DIR/httpx_targets.txt" >/dev/null

nuclei -silent -jsonl -rl "$RATE_LIMIT" -retries 1 \
  -severity "$INCLUDE_SEVERITY" \
  -etags dos,bruteforce,destructive,rce,delete,credential-stuffing,active,misuse \
  -nt -ni -no-interactsh \
  -udata "$RUN_DIR/" \
  -l "$RUN_DIR/httpx_targets.txt" \
  -o "$NUCLEI_OUT" || true

# 6) Summaries
# Summarize by severity & template id
if command -v jq >/dev/null; then
  jq -r 'select(.info != null) | [.info.severity, .info.name, .templateID, .host] | @tsv' "$NUCLEI_OUT" \
    | sort | tee "$RUN_DIR/summary.tsv" >/dev/null || true
fi

# 7) Write a run README
cat > "$RUN_DIR/README.md" <<EOF
# MBOS Safe Hunt run @ $TS

- Rate limit: $RATE_LIMIT req/s
- Severities: $INCLUDE_SEVERITY
- Dry run: $DRY_RUN
- Alive count: $(wc -l < "$RUN_DIR/httpx_live.txt" 2>/dev/null || echo 0)
- Nuclei lines: $(wc -l < "$NUCLEI_OUT" 2>/dev/null || echo 0)

## Notes
- Out-of-scope hosts filtered: $(wc -l < "$OOS_FILE" 2>/dev/null || echo 0)
- Denylist regex in use from scripts/denylist_regex.txt
- Active scanning restricted to ports listed in scripts/allowed_ports.txt
- Avoids destructive nuclei tags.
EOF

echo "[+] Done. Results in $RUN_DIR" >&2
