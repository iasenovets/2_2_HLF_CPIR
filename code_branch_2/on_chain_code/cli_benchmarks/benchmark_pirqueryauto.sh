#!/bin/bash
set -u

EPOCHS=20
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== Benchmarking PIRQueryAuto ==="
echo "Results directory: $RESULTS_DIR"

# ---- CSV headers ----
echo "epoch,execution_time_ms,result_len_b64" > "$RESULTS_DIR/PIRQueryAuto_server_timing.csv"
echo "epoch,start_time,end_time,client_duration_ms" > "$RESULTS_DIR/PIRQueryAuto_client_timing.csv"
echo "epoch,CONTAINER,CPU %,MEM USAGE / LIMIT,MEM %,NET I/O,BLOCK I/O" > "$RESULTS_DIR/docker_stats.csv"

# ---- helpers ----

# Extract execution_time_ms (and optionally result_len_b64) from either:
# 1) raw JSON (preferred): {"execution_time_ms":..., "result_len_b64":..., ...}
# 2) wrapped: ... payload:"{\"execution_time_ms\":..., \"result_len_b64\":...}"
# Prints two CSV-safe fields to stdout:  <time>,<len>
extract_execution_time() {
    local response="$1"

    # strip ANSI + CR
    local clean
    clean=$(printf "%s" "$response" \
        | sed -E 's/\x1b\[[0-9;]*m//g' \
        | tr -d '\r')

    # --- Try RAW JSON line (last line that starts with '{') ---
    local json_line
    json_line=$(printf "%s\n" "$clean" | awk '/^\{/{buf=$0} END{print buf}')

    if [ -n "$json_line" ]; then
        if command -v jq >/dev/null 2>&1; then
            local t len
            t=$(printf "%s" "$json_line" | jq -r '.execution_time_ms // empty' 2>/dev/null)
            len=$(printf "%s" "$json_line" | jq -r '.result_len_b64 // empty' 2>/dev/null)
            if [ -n "$t" ]; then
                printf "%s,%s" "$t" "$len"
                return
            fi
        fi
        # Fallback regex (no jq)
        local t2 len2
        t2=$(printf "%s" "$json_line" | grep -oE '"execution_time_ms":[0-9.]+' | head -1 | cut -d: -f2)
        len2=$(printf "%s" "$json_line" | grep -oE '"result_len_b64":[0-9]+' | head -1 | cut -d: -f2)
        if [ -n "$t2" ]; then
            printf "%s,%s" "$t2" "$len2"
            return
        fi
    fi

    # --- Try WRAPPED payload:"{...}" ---
    local wrapped
    wrapped=$(printf "%s" "$clean" | sed -n 's/.*payload:"\({.*}\)".*/\1/p')
    if [ -n "$wrapped" ]; then
        wrapped=$(printf "%s" "$wrapped" | sed 's/\\"/"/g')
        if command -v jq >/dev/null 2>&1; then
            local t3 len3
            t3=$(printf "%s" "$wrapped" | jq -r '.execution_time_ms // empty' 2>/dev/null)
            len3=$(printf "%s" "$wrapped" | jq -r '.result_len_b64 // empty' 2>/dev/null)
            if [ -n "$t3" ]; then
                printf "%s,%s" "$t3" "$len3"
                return
            fi
        fi
        local t4 len4
        t4=$(printf "%s" "$wrapped" | grep -oE '"execution_time_ms":[0-9.]+' | head -1 | cut -d: -f2)
        len4=$(printf "%s" "$wrapped" | grep -oE '"result_len_b64":[0-9]+' | head -1 | cut -d: -f2)
        if [ -n "$t4" ]; then
            printf "%s,%s" "$t4" "$len4"
            return
        fi
    fi

    return 1
}

# Parse docker stats table and append to one CSV (epoch-prefixed)
append_docker_stats_csv() {
    local epoch="$1"
    local stats_text="$2"
    local out_csv="$3"
    printf "%s" "$stats_text" \
      | sed '1d' \
      | awk -F',' -v e="$epoch" 'NF>=6 {printf "%s,%s,%s,%s,%s,%s,%s\n", e,$1,$2,$3,$4,$5,$6}' \
      >> "$out_csv"
}

success_count=0

for ((i=1; i<=EPOCHS; i++)); do
    echo -n "Epoch $i: "

    # Snapshot (post-call tends to be more indicative)
    pre_stats=$(docker stats --no-stream --format "table {{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}}" \
        peer0.org1.example.com orderer0.group1.orderer.example.com 2>/dev/null)

    # Client timing + capture response
    start_client=$(date +%s%3N)
    response=$(./fabric-docker.sh chaincode query "peer0.org1.example.com" "channel-mini" "on_chain_pir" \
        '{"Args":["PIRQueryAuto"]}' 2>&1)
    end_client=$(date +%s%3N)
    client_duration=$((end_client - start_client))

    post_stats=$(docker stats --no-stream --format "table {{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}}" \
        peer0.org1.example.com orderer0.group1.orderer.example.com 2>/dev/null)

    # Record stats (choose post; uncomment pre if you want both)
    append_docker_stats_csv "$i" "$post_stats" "$RESULTS_DIR/docker_stats.csv"
    # append_docker_stats_csv "$i" "$pre_stats" "$RESULTS_DIR/docker_stats.csv"

    # Extract server-side time (+ optional result_len_b64)
    # Will print "time,len" or fail
    tl=$(extract_execution_time "$response" || true)

    if [ -n "${tl:-}" ]; then
        exec_time=${tl%%,*}
        res_len=${tl#*,}
        echo "Server: ${exec_time}ms, Client: ${client_duration}ms, ResultLenB64: ${res_len:-NA}"
        echo "$i,$exec_time,${res_len}" >> "$RESULTS_DIR/PIRQueryAuto_server_timing.csv"
        echo "$i,$start_client,$end_client,$client_duration" >> "$RESULTS_DIR/PIRQueryAuto_client_timing.csv"
        ((success_count++))
    else
        echo "FAILED - no execution_time_ms in response"
        echo "$i,FAILED," >> "$RESULTS_DIR/PIRQueryAuto_server_timing.csv"
        echo "$i,$start_client,$end_client,$client_duration" >> "$RESULTS_DIR/PIRQueryAuto_client_timing.csv"
        # For debugging, you can dump the raw response:
        # printf "%s\n" "$response" > "$RESULTS_DIR/PIRQueryAuto_epoch_${i}_response.txt"
    fi

    sleep 1
done

# ---- summary ----
if [ $success_count -gt 0 ]; then
    server_avg=$(awk -F',' '$2 != "FAILED" {sum+=$2; n++} END{if(n) printf "%.2f", sum/n}' "$RESULTS_DIR/PIRQueryAuto_server_timing.csv")
    server_min=$(awk -F',' '$2 != "FAILED" && (min=="" || $2<min){min=$2} END{if(min!="") printf "%.2f", min}' "$RESULTS_DIR/PIRQueryAuto_server_timing.csv")
    server_max=$(awk -F',' '$2 != "FAILED" && (max=="" || $2>max){max=$2} END{if(max!="") printf "%.2f", max}' "$RESULTS_DIR/PIRQueryAuto_server_timing.csv")

    client_avg=$(awk -F',' 'NR>1 {sum+=$4; n++} END{if(n) printf "%.2f", sum/n}' "$RESULTS_DIR/PIRQueryAuto_client_timing.csv")
    client_min=$(awk -F',' 'NR>1 && (min=="" || $4<min){min=$4} END{if(min!="") printf "%.2f", min}' "$RESULTS_DIR/PIRQueryAuto_client_timing.csv")
    client_max=$(awk -F',' 'NR>1 && (max=="" || $4>max){max=$4} END{if(max!="") printf "%.2f", max}' "$RESULTS_DIR/PIRQueryAuto_client_timing.csv")

    echo ""
    echo "=== SERVER-SIDE TIMING (PIRQueryAuto) ==="
    echo "Successful: $success_count/$EPOCHS"
    echo "Average: ${server_avg}ms"
    echo "Range: ${server_min}ms - ${server_max}ms"

    echo ""
    echo "=== CLIENT-SIDE TIMING ==="
    echo "Average: ${client_avg}ms"
    echo "Range: ${client_min}ms - ${client_max}ms"

    echo ""
    echo "=== NETWORK OVERHEAD (approx) ==="
    overhead=$(echo "scale=2; ${client_avg:-0} - ${server_avg:-0}" | bc)
    echo "Average network overhead: ${overhead}ms"
else
    echo "No successful runs with server timing!"
fi

echo ""
echo "Benchmark complete! Results in: $RESULTS_DIR"
