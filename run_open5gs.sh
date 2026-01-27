#!/bin/bash
set -e

BASE_DIR="$HOME/srsRAN_main/open5gs"
BIN_DIR="$BASE_DIR/install/bin"
CONF_DIR="$BASE_DIR/install/etc/open5gs"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"
cd "$BASE_DIR"

NFS=(
  nrfd:nrf.yaml
  udmd:udm.yaml
  ausfd:ausf.yaml
  pcfd:pcf.yaml
  amfd:amf.yaml
  smfd:smf.yaml
  upfd:upf.yaml
  bsfd:bsf.yaml
  hssd:hss.yaml
  mmed:mme.yaml
  nssfd:nssf.yaml
  pcrfd:pcrf.yaml
  scpd:scp.yaml
  sgwcd:sgwc.yaml
  sgwud:sgwu.yaml
  udrd:udr.yaml
)

for item in "${NFS[@]}"; do
  bin="open5gs-${item%%:*}"
  conf="$CONF_DIR/${item##*:}"
  log="$LOG_DIR/${item%%:*}.log"

  echo "[실행] $bin -c $conf | 로그: $log"
  # 터미널에도 출력 + 로그파일에도 저장
  $BIN_DIR/$bin -c "$conf" 2>&1 | tee "$log" &
done

echo
echo "[+] Open5GS 모든 프로세스 실행됨"
echo "    로그 파일: $LOG_DIR/*.log"
echo "    중지하려면: pkill -f open5gs-"
wait
