#!/bin/sh
cd "$(dirname "$0")"
if [ -f server.pid ]; then
    kill "$(cat server.pid)" 2>/dev/null && echo "stopped (pid $(cat server.pid))"
    rm -f server.pid
else
    echo "not running"
fi
