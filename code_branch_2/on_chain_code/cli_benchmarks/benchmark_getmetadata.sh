#!/bin/bash


EPOCHS=20
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== Benchmarking GetMetadata ==="
echo "Results directory: $RESULTS_DIR"

# ---- CSV headers ----
echo "epoch,execution_time_ms" > "$RESULTS_DIR/GetMetadata_server_timing.csv"
echo "epoch,start_time,end_time,client_duration_ms" > "$RESULTS_DIR/GetMetadata_client_timing.csv"
echo "epoch,CONTAINER,CPU %,MEM USAGE / LIMIT,MEM %,NET I/O,BLOCK I/O" > "$RESULTS_DIR/docker_stats.csv"

# ---- helpers ----
extract_execution_time() {
    local response="$1"

    # strip ANSI + CR
    local clean
    clean=$(printf "%s" "$response" \
        | sed -E 's/\x1b\[[0-9;]*m//g' \
        | tr -d '\r')

    # try RAW JSON: take the last line that starts with '{'
    local json_line
    json_line=$(printf "%s\n" "$clean" | awk '/^\{/{buf=$0} END{print buf}')

    if [ -n "$json_line" ]; then
        # Prefer jq if available (robust)
        if command -v jq >/dev/null 2>&1; then
            local val
            val=$(printf "%s" "$json_line" | jq -r '.execution_time_ms // empty' 2>/dev/null)
            [ -n "$val" ] && { printf "%s" "$val"; return; }
        fi
        # Fallback: regex
        local val2
        val2=$(printf "%s" "$json_line" | grep -oE '"execution_time_ms":[0-9. ]+' | head -1 | cut -d: -f2 | tr -d ' ')
        [ -n "$val2" ] && { printf "%s" "$val2"; return; }
    fi

    # try WRAPPED payload:"{...}"
    local wrapped
    wrapped=$(printf "%s" "$clean" | sed -n 's/.*payload:"\({.*}\)".*/\1/p')
    if [ -n "$wrapped" ]; then
        wrapped=$(printf "%s" "$wrapped" | sed 's/\\"/"/g')
        if command -v jq >/dev/null 2>&1; then
            local val3
            val3=$(printf "%s" "$wrapped" | jq -r '.execution_time_ms // empty' 2>/dev/null)
            [ -n "$val3" ] && { printf "%s" "$val3"; return; }
        fi
        local val4
        val4=$(printf "%s" "$wrapped" | grep -oE '"execution_time_ms":[0-9.]+' | head -1 | cut -d: -f2)
        [ -n "$val4" ] && { printf "%s" "$val4"; return; }
    fi

    # nothing found -> print nothing
    return 1
}

append_docker_stats_csv() {
    local epoch="$1"
    local stats_text="$2"
    local out_csv="$3"
    echo "$stats_text" \
      | sed '1d' \
      | awk -F',' -v e="$epoch" 'NF>=6 {printf "%s,%s,%s,%s,%s,%s,%s\n", e,$1,$2,$3,$4,$5,$6}' \
      >> "$out_csv"
}

success_count=0

for ((i=1; i<=EPOCHS; i++)); do
    echo -n "Epoch $i: "

    # snapshot system load (optional pre)
    pre_stats=$(docker stats --no-stream --format "table {{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}}" \
        peer0.org1.example.com orderer0.group1.orderer.example.com 2>/dev/null)

    # client timing + capture response
    start_client=$(date +%s%3N)
    response=$(./fabric-docker.sh chaincode query "peer0.org1.example.com" "channel-mini" "on_chain_pir" \
        '{"Args":["GetMetadata"]}' 2>&1)
    end_client=$(date +%s%3N)
    client_duration=$((end_client - start_client))

    # snapshot system load (post)
    post_stats=$(docker stats --no-stream --format "table {{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}}" \
        peer0.org1.example.com orderer0.group1.orderer.example.com 2>/dev/null)

    # prefer post-call stats in the CSV
    append_docker_stats_csv "$i" "$post_stats" "$RESULTS_DIR/docker_stats.csv"
    # if you also want pre-call stats in same CSV, uncomment:
    # append_docker_stats_csv "$i" "$pre_stats" "$RESULTS_DIR/docker_stats.csv"

    # server-side time from payload:"{...}"
    execution_time=$(extract_execution_time "$response")

    if [ -n "${execution_time:-}" ] && [[ "$execution_time" != "null" ]]; then
        echo "Server: ${execution_time}ms, Client: ${client_duration}ms"
        echo "$i,$execution_time" >> "$RESULTS_DIR/GetMetadata_server_timing.csv"
        echo "$i,$start_client,$end_client,$client_duration" >> "$RESULTS_DIR/GetMetadata_client_timing.csv"
        ((success_count++))
    else
        echo "FAILED - no execution_time_ms in response"
        echo "$i,FAILED" >> "$RESULTS_DIR/GetMetadata_server_timing.csv"
        echo "$i,$start_client,$end_client,$client_duration" >> "$RESULTS_DIR/GetMetadata_client_timing.csv"
        # for debugging, you can save the raw response:
        # printf "%s\n" "$response" > "$RESULTS_DIR/GetMetadata_epoch_${i}_response.txt"
    fi

    sleep 1
done

# ---- summary ----
if [ $success_count -gt 0 ]; then
    server_avg=$(awk -F',' '$2 != "FAILED" {sum+=$2; n++} END{if(n) printf "%.2f", sum/n}' "$RESULTS_DIR/GetMetadata_server_timing.csv")
    server_min=$(awk -F',' '$2 != "FAILED" && (min=="" || $2<min){min=$2} END{if(min!="") printf "%.2f", min}' "$RESULTS_DIR/GetMetadata_server_timing.csv")
    server_max=$(awk -F',' '$2 != "FAILED" && (max=="" || $2>max){max=$2} END{if(max!="") printf "%.2f", max}' "$RESULTS_DIR/GetMetadata_server_timing.csv")

    client_avg=$(awk -F',' 'NR>1 {sum+=$4; n++} END{if(n) printf "%.2f", sum/n}' "$RESULTS_DIR/GetMetadata_client_timing.csv")
    client_min=$(awk -F',' 'NR>1 && (min=="" || $4<min){min=$4} END{if(min!="") printf "%.2f", min}' "$RESULTS_DIR/GetMetadata_client_timing.csv")
    client_max=$(awk -F',' 'NR>1 && (max=="" || $4>max){max=$4} END{if(max!="") printf "%.2f", max}' "$RESULTS_DIR/GetMetadata_client_timing.csv")

    echo ""
    echo "=== SERVER-SIDE TIMING (GetMetadata) ==="
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
