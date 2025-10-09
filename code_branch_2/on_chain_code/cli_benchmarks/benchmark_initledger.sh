#!/bin/bash

EPOCHS=20
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== Benchmarking InitLedger (Server Timing) ==="
echo "Results directory: $RESULTS_DIR"

# ---- CSV headers ----
echo "epoch,execution_time_ms" > "$RESULTS_DIR/InitLedger_server_timing.csv"
echo "epoch,start_time,end_time,client_duration_ms" > "$RESULTS_DIR/InitLedger_client_timing.csv"
echo "epoch,CONTAINER,CPU %,MEM USAGE / LIMIT,MEM %,NET I/O,BLOCK I/O" > "$RESULTS_DIR/docker_stats.csv"

# ---- helpers ----
extract_execution_time() {
    local response="$1"
    printf "%s" "$response" \
      | sed -E 's/\x1b\[[0-9;]*m//g' \
      | tr -d '\r' \
      | sed -n 's/.*payload:"\({.*}\)".*/\1/p' \
      | sed 's/\\"/"/g' \
      | jq -r '.execution_time_ms' 2>/dev/null
}

# Parse the "table" from `docker stats --no-stream` and append to one CSV
append_docker_stats_csv() {
    local epoch="$1"
    local stats_text="$2"
    local out_csv="$3"
    # Drop header row, then prepend epoch and append to CSV
    # Fields are already comma-separated by --format "table A,B,C,..."
    echo "$stats_text" \
      | sed '1d' \
      | awk -F',' -v e="$epoch" 'NF>=6 {printf "%s,%s,%s,%s,%s,%s,%s\n", e,$1,$2,$3,$4,$5,$6}' \
      >> "$out_csv"
}

success_count=0

for ((i=1; i<=EPOCHS; i++)); do
    echo -n "Epoch $i: "

    # --- (optional) one pre-snapshot ---
    pre_stats=$(docker stats --no-stream --format "table {{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}}" \
        peer0.org1.example.com orderer0.group1.orderer.example.com 2>/dev/null)

    # --- invoke + client timing ---
    start_client=$(date +%s%3N)
    response=$(./fabric-docker.sh chaincode invoke "peer0.org1.example.com" "channel-mini" "on_chain_pir" '{"Args":["InitLedger","64","128","","","",""]}' "" 2>&1)
    end_client=$(date +%s%3N)
    client_duration=$((end_client - start_client))

    # --- one post-snapshot (usually more interesting) ---
    post_stats=$(docker stats --no-stream --format "table {{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}}" \
        peer0.org1.example.com orderer0.group1.orderer.example.com 2>/dev/null)

    # Append whichever you prefer (post snapshot recommended)
    append_docker_stats_csv "$i" "$post_stats" "$RESULTS_DIR/docker_stats.csv"
    # If you also want pre-call stats, uncomment:
    # append_docker_stats_csv "$i" "$pre_stats" "$RESULTS_DIR/docker_stats.csv"

    # --- extract server exec time ---
    execution_time=$(extract_execution_time "$response")

    if [ -n "$execution_time" ]; then
        echo "Server: ${execution_time}ms, Client: ${client_duration}ms"
        echo "$i,$execution_time" >> "$RESULTS_DIR/InitLedger_server_timing.csv"
        echo "$i,$start_client,$end_client,$client_duration" >> "$RESULTS_DIR/InitLedger_client_timing.csv"
        ((success_count++))
    else
        echo "FAILED - no execution time in response"
        echo "$i,FAILED" >> "$RESULTS_DIR/InitLedger_server_timing.csv"
        echo "$i,$start_client,$end_client,$client_duration" >> "$RESULTS_DIR/InitLedger_client_timing.csv"
    fi

    # If you still want per-epoch raw logs for deep dives, uncomment:
    # printf "%s\n" "$response" > "$RESULTS_DIR/InitLedger_epoch_${i}_response.txt"

    sleep 2
done

# ---- stats summary (unchanged) ----
if [ $success_count -gt 0 ]; then
    server_avg=$(awk -F',' '$2 != "FAILED" {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count}' "$RESULTS_DIR/InitLedger_server_timing.csv")
    server_min=$(awk -F',' '$2 != "FAILED" && (min=="" || $2<min) {min=$2} END {printf "%.2f", min}' "$RESULTS_DIR/InitLedger_server_timing.csv")
    server_max=$(awk -F',' '$2 != "FAILED" && (max=="" || $2>max) {max=$2} END {printf "%.2f", max}' "$RESULTS_DIR/InitLedger_server_timing.csv")

    client_avg=$(awk -F',' 'NR>1 {sum+=$4} END {printf "%.2f", sum/(NR-1)}' "$RESULTS_DIR/InitLedger_client_timing.csv")
    client_min=$(awk -F',' 'NR>1 && (min=="" || $4<min) {min=$4} END {printf "%.2f", min}' "$RESULTS_DIR/InitLedger_client_timing.csv")
    client_max=$(awk -F',' 'NR>1 && (max=="" || $4>max) {max=$4} END {printf "%.2f", max}' "$RESULTS_DIR/InitLedger_client_timing.csv")

    echo ""
    echo "=== SERVER-SIDE TIMING (Accurate) ==="
    echo "Successful: $success_count/$EPOCHS"
    echo "Average: ${server_avg}ms"
    echo "Range: ${server_min}ms - ${server_max}ms"

    echo ""
    echo "=== CLIENT-SIDE TIMING (With Network Overhead) ==="
    echo "Average: ${client_avg}ms"
    echo "Range: ${client_min}ms - ${client_max}ms"

    echo ""
    echo "=== NETWORK OVERHEAD ==="
    overhead=$(echo "scale=2; $client_avg - $server_avg" | bc)
    echo "Average network overhead: ${overhead}ms"
else
    echo "No successful runs with server timing!"
fi

echo ""
echo "Benchmark complete! Results in: $RESULTS_DIR"
