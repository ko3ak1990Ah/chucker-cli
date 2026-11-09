#!/bin/sh
cd "$(dirname "$0")"
if [ -f server.pid ] && kill -0 "$(cat server.pid)" 2>/dev/null; then
    echo "already running (pid $(cat server.pid))"
    exit 0
fi
nohup python3 -u server.py >server.log 2>&1 &
echo $! >server.pid
echo "started (pid $(cat server.pid)), log: $(pwd)/server.log"
