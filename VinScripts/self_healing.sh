#!/data/data/com.termux/files/usr/bin/bash
while true; do if ! pgrep -f "main_execution_enc"; then ~/VinScripts/main_execution_enc; fi; sleep 5; done
