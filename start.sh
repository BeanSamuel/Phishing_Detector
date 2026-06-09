#!/bin/bash
# Startup script for PhishGuard

# Get the absolute path of the project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Check if conda environment phishing_detector exists
conda env list | grep -q "phishing_detector"
if [ $? -ne 0 ]; then
  echo "Error: Conda environment 'phishing_detector' does not exist."
  exit 1
fi

echo "Starting PhishGuard API Backend..."
cd "$PROJECT_ROOT/backend"
uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "Waiting for backend to start..."
sleep 3

# Verify backend started successfully
if ! kill -0 $BACKEND_PID 2>/dev/null; then
  echo "Error: Backend failed to start. Please check the logs."
  exit 1
fi

echo "Starting PhishGuard Gradio Frontend..."
cd "$PROJECT_ROOT/frontend"
python app.py &
FRONTEND_PID=$!

# Wait to check if frontend launched successfully
sleep 2
if ! kill -0 $FRONTEND_PID 2>/dev/null; then
  echo "Error: Frontend failed to start (it may have exited or port 7860 was busy)."
  kill $BACKEND_PID 2>/dev/null
  exit 1
fi

cleanup() {
  echo ""
  echo "Stopping PhishGuard services..."
  kill $BACKEND_PID 2>/dev/null
  kill $FRONTEND_PID 2>/dev/null
  exit 0
}

trap cleanup SIGINT SIGTERM

wait
