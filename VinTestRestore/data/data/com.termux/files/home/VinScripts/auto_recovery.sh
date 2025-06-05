#!/bin/bash
PROCESS="gotop"
pgrep $PROCESS > /dev/null || (echo "Restarting $PROCESS..." && $PROCESS &)
