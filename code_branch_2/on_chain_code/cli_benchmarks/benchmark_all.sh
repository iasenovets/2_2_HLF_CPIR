#!/bin/bash

# Master script to run all benchmarks
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="benchmark_results_${TIMESTAMP}"

echo "=== Running all benchmarks ==="
echo "Results directory: $RESULTS_DIR"

# Set the results directory for all scripts
export BENCHMARK_RESULTS_DIR="$RESULTS_DIR"

# Run each benchmark
echo ""
echo "1. Running InitLedger benchmark..."
./benchmark_initledger.sh

echo ""
echo "2. Running GetMetadata benchmark..."
./benchmark_getmetadata.sh

echo ""
echo "3. Running PIRQueryAuto benchmark..."
./benchmark_pirqueryauto.sh

echo ""
echo "=== ALL BENCHMARKS COMPLETE ==="
echo "Results in: $RESULTS_DIR"

# Generate summary
echo "=== SUMMARY ===" > "$RESULTS_DIR/benchmark_summary.txt"
for function in InitLedger GetMetadata PIRQueryAuto; do
    if [ -f "$RESULTS_DIR/${function}_timing.csv" ]; then
        avg=$(awk -F',' 'NR>1 {sum+=$4} END {print sum/(NR-1)}' "$RESULTS_DIR/${function}_timing.csv")
        echo "$function: ${avg}ms average" >> "$RESULTS_DIR/benchmark_summary.txt"
    fi
done

cat "$RESULTS_DIR/benchmark_summary.txt"
