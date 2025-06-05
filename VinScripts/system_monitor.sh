#!/data/data/com.termux/files/usr/bin/bash
while true; do
  TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
  CPU_USAGE=$(top -b -n 1 | grep "Cpu(s)" | awk "{print \$2 + \$4}")
  MEM_USAGE=$(free -m | awk "NR==2 {print \$3}")
  echo "$TIMESTAMP - CPU: $CPU_USAGE% | RAM: $MEM_USAGE MB" >> ~/VinLogs/system_health.log
  sleep 5
done
  if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then echo "⚠️ High CPU Usage Detected: $CPU_USAGE%"; fi
  if (( $MEM_USAGE > 500 )); then echo "⚠️ High RAM Usage Detected: $MEM_USAGE MB"; fi
