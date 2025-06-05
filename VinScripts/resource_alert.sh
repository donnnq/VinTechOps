#!/bin/bash
CPU_LOAD=$(grep "cpu " /proc/stat | awk '{print ($2+$4)*100/($2+$4+$5)}')
if [[ "$CPU_LOAD" > "85" ]]; then echo "⚠️ High CPU Usage Detected: $CPU_LOAD%"; fi
