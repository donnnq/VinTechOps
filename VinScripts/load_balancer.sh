#!/data/data/com.termux/files/usr/bin/bash
while true; do
  CPU_USAGE=$(top -b -n 1 | grep "Cpu(s)" | awk "{print \$2 + \$4}")
  MEM_USAGE=$(free -m | awk "NR==2 {print \$3}")
  if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then renice -n 10 -p $(pgrep -f "main_execution_enc"); fi
  if (( $MEM_USAGE > 500 )); then kill -STOP $(pgrep -f "resource_alert.sh"); fi
  sleep 5
done
