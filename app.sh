#!/bin/bash
NUM_WORKERS=8
ADDR="localhost"
PORT=8080
APP_MODULE="coordinator.app"
APP_NAME="app"

while getopts ":st" opt; do
    case $opt in
        s)  # Start Gunicorn with nohup if not already running
            if ! pgrep -x "gunicorn" > /dev/null; then
                echo "Starting Gunicorn with nohup..."
                nohup gunicorn -k gevent -w $NUM_WORKERS -b $ADDR:$PORT $APP_MODULE:$APP_NAME > gunicorn.log 2>&1 &
                echo "Gunicorn started."
            else
                echo "Gunicorn is already running."
            fi
            ;;
        t)  # Terminate all Gunicorn processes
            pkill -TERM -f "gunicorn"
            echo "Terminating all Gunicorn processes gracefully..."
            ;;
        \?) # Invalid option
            echo "Invalid option: -$OPTARG" >&2
            echo "Usage: $0 [-s to start Gunicorn] [-t to terminate Gunicorn processes]" >&2
            exit 1
            ;;
    esac
done
