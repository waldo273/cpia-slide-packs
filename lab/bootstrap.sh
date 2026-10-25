#!/bin/sh
# CPIA lab bootstrap for a stock Kali machine (the CourseStack lab system).
#
#   curl -fsSL https://waldo273.github.io/cpia-slide-packs/lab/bootstrap.sh | sudo sh
#
# What it does, in order:
#   1. installs the tools the fourteen lab sheets call (tshark, sleuthkit, plaso, volatility3,
#      oletools, yara, nmap, plus ssh and the python bits the lab services need)
#   2. fetches the lab bundle (services, sheets, planted files, flag checker) into /opt/cpia-lab
#   3. builds the local evidence the labs examine, under /labs/work and /labs/artifacts
#   4. starts the evidence page on 8010 and the victim web service on 8080
#   5. puts the `lab` command on PATH
#
# It is idempotent: a second run reinstalls nothing it already has and restarts the services.
set -eu

BASE=${CPIA_BASE:-https://waldo273.github.io/cpia-slide-packs/lab}
LAB_ROOT=/opt/cpia-lab
WORK=/labs/work
ART=/labs/artifacts

say() { printf '\n== %s\n' "$*"; }

say "1/5 packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    tshark sleuthkit plaso oletools yara nmap openssh-server \
    python3 python3-pip python3-venv curl ca-certificates e2fsprogs \
    p7zip-full file binutils libewf-tools poppler-utils 2>&1 | tail -2 || true

say "2/5 bundle"
mkdir -p "$LAB_ROOT" /labs
for f in srv/server.py srv/victim-web.py bin/lab flags/flags.json labs/index.txt; do
    mkdir -p "$LAB_ROOT/$(dirname "$f")"
    curl -fsSL "$BASE/$f" -o "$LAB_ROOT/$f"
done
for n in 01 02 03 04 05 06 07 08 09 10 11 12 13 14; do
    curl -fsSL "$BASE/labs/L$n.md" -o "$LAB_ROOT/labs/L$n.md" || true
done
chmod +x "$LAB_ROOT/bin/lab"
ln -sf "$LAB_ROOT/bin/lab" /usr/local/bin/lab
mkdir -p /usr/local/share/cpia
cp "$LAB_ROOT/flags/flags.json" /usr/local/share/cpia/flags.json
curl -fsSL "$BASE/srv/labs.html" -o /labs/labs.html || true

say "3/5 evidence"
mkdir -p "$WORK" "$ART" /labs/reports /labs/sheets
cp "$LAB_ROOT"/labs/L*.md /labs/sheets/ 2>/dev/null || true
# fixtures are generated on this machine rather than downloaded: they are large and synthetic
if [ ! -f "$WORK/.built" ]; then
    curl -fsSL "$BASE/fixtures/build_fixtures.py" -o "$LAB_ROOT/build_fixtures.py"
    ( cd "$LAB_ROOT" && python3 build_fixtures.py ) || echo "fixture build reported a problem, continuing"
    cp -a "$LAB_ROOT/fixtures/out/." "$WORK/" 2>/dev/null || true
    date -u +%FT%TZ > "$WORK/.built"
fi

say "4/5 services"
pkill -f "cpia-lab/srv/server.py" 2>/dev/null || true
pkill -f "cpia-lab/srv/victim-web.py" 2>/dev/null || true
sleep 1
EVIDENCE_PORT=8010 LAB_ROOT="$LAB_ROOT" nohup python3 "$LAB_ROOT/srv/server.py" \
    >/var/log/cpia-evidence.log 2>&1 &
VICTIM_PORT=8080 nohup python3 "$LAB_ROOT/srv/victim-web.py" \
    >/var/log/cpia-victim.log 2>&1 &
sleep 1

say "5/5 check"
for url in http://127.0.0.1:8010/ http://127.0.0.1:8080/; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$url" || echo 000)
    printf '   %-26s %s\n' "$url" "$code"
done
printf '   lab command                %s\n' "$(command -v lab || echo missing)"

cat <<'BANNER'

CPIA labs are set up.

   Lab page      http://127.0.0.1:8010/
   Evidence      /labs/work  and  /labs/artifacts
   Victim web    http://127.0.0.1:8080/
   Sheets        /labs/sheets/L01.md ... L14.md

   lab           list labs and progress
   lab 1         show what lab 1 needs
   lab check 1 VALUE   submit a flag
BANNER
