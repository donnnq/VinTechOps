#!/data/data/com.termux/files/usr/bin/bash
TIMESTAMP=$(date "+%Y-%m-%d_%H-%M-%S")
tar -czvf ~/VinBackups/VinTechOps_Backup_$TIMESTAMP.tar.gz ~/VinScripts ~/VinLogs 
echo "Backup Completed: $TIMESTAMP"
2>> ~/VinLogs/backup_errors.log
