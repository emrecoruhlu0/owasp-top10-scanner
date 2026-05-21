#!/bin/sh
if [ "$1" = "web" ]; then
    exec uvicorn web.app:app --host 0.0.0.0 --port 8000
else
    exec python /app/guvenlik_proje/main.py "$@"
fi
