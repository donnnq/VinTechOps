#!/bin/bash
DISK_FREE=$(df -h ~ | awk 'NR==2 {print $4}')
if [[ "$DISK_FREE" < "1G" ]]; then logrotate --force ~/VinLogs/logrotate.conf; fi
