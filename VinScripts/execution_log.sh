#!/data/data/com.termux/files/usr/bin/bash
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "$TIMESTAMP - Command Executed: $@" >> ~/VinScripts/execution_history.log
