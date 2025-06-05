#!/bin/bash
echo "System Health Report - $(date)" > ~/VinLogs/system_health.log
uptime >> ~/VinLogs/system_health.log
df -h >> ~/VinLogs/system_health.log
