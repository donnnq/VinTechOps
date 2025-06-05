#!/bin/bash
SYS_INFO=$(uname -a)
if [[ "$SYS_INFO" == *"Android"* ]]; then echo "Running in Termux"; else echo "Unknown system"; fi
