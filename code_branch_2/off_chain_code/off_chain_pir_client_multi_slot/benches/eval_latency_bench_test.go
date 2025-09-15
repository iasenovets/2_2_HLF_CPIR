package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// Number of times to measure latency (epochs)
const epochs = 30

// Test configuration
const (
	targetIndex = 13    // Index for PIR query
	numRecords  = "64"  // Number of records for InitLedger
	maxJsonLen  = "512" // Max JSON length per record
	channelName = "channel_rich"
	serverURL   = "http://localhost:8080/invoke"
)

// BenchmarkEvalLatency measures ONLY the on-chain PIR evaluation latency
func BenchmarkEvalLatency(b *testing.B) {
	// ❶ Generate HE keys (single time for all epochs)
	params, _, pk, err := GenKeys()
	if err != nil {
		b.Fatal(err)
	}

	// ❷ Initialize PTDB on Fabric chaincode
	_, err = call("InitLedger", numRecords, maxJsonLen, channelName)
	if err != nil {
		b.Fatal("InitLedger failed:", err)
	}

	// Get slotsPerRecord
	slotsStr, _ := call("GetSlotsPerRecord")
	slotsPerRec, _ := strconv.Atoi(slotsStr)

	// Get total number of records
	totalStr, _ := call("PublicQueryALL")
	dbSize, _ := strconv.Atoi(totalStr)

	// Encrypt PIR query vector
	encQueryB64, _, err := EncryptQueryBase64(params, pk, targetIndex, dbSize, slotsPerRec)
	if err != nil {
		b.Fatal(err)
	}

	// ❸ Create CSV file for results
	f, err := os.Create("eval_latency.csv")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"epoch", "latency_ms"}) // CSV header

	// ❹ Measure server evaluation latency
	for epoch := 1; epoch <= epochs; epoch++ {
		start := time.Now()
		_, err := call("PIRQuery", encQueryB64) // server performs homomorphic eval
		if err != nil {
			b.Fatalf("epoch %d: %v", epoch, err)
		}
		elapsed := time.Since(start)
		latMs := float64(elapsed.Nanoseconds()) / 1e6
		w.Write([]string{fmt.Sprint(epoch), fmt.Sprintf("%.3f", latMs)})
		fmt.Printf("[EVAL-BENCH] Epoch %d → %.3f ms\n", epoch, latMs)
	}
}
