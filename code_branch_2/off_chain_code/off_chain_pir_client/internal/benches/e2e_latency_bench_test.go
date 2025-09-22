package benches

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// Benchmark configuration
const (
	epochs      = 30
	targetIndex = 13    // Index for PIR query
	numRecords  = "64"  // Number of records for InitLedger
	maxJsonLen  = "512" // Max JSON size per record
	channelName = "channel_rich"
	serverURL   = "http://localhost:8080/invoke"
)

// BenchmarkEndToEnd measures Enc + Eval + Dec latency (ms)
func BenchmarkEndToEnd(b *testing.B) {
	// 1. Generate BGV keys and params
	params, sk, pk, err := GenKeys()
	if err != nil {
		b.Fatal(err)
	}

	// 2. Initialize ledger on the server
	_, err = call("InitLedger", numRecords, maxJsonLen, channelName)
	if err != nil {
		b.Fatalf("InitLedger failed: %v", err)
	}

	// Get slotsPerRecord
	slotsStr, _ := call("GetSlotsPerRecord")
	slotsPerRec, _ := strconv.Atoi(slotsStr)

	// Get DB size
	totalStr, _ := call("PublicQueryALL")
	dbSize, _ := strconv.Atoi(totalStr)

	// 3. Prepare CSV output
	f, err := os.Create("pir_end_to_end_latency.csv")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"epoch", "enc_ms", "eval_ms", "dec_ms", "total_ms"})

	// 4. Run benchmark for N epochs
	for epoch := 1; epoch <= epochs; epoch++ {
		// ---- Encryption ----
		startEnc := time.Now()
		encQueryB64, _, err := EncryptQueryBase64(params, pk, targetIndex, dbSize, slotsPerRec)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
		elapsedEnc := time.Since(startEnc).Milliseconds()

		// ---- Evaluation (PIRQuery) ----
		startEval := time.Now()
		encResB64, err := call("PIRQuery", encQueryB64)
		if err != nil {
			b.Fatalf("PIRQuery failed: %v", err)
		}
		elapsedEval := time.Since(startEval).Milliseconds()

		// ---- Decryption ----
		startDec := time.Now()
		_, err = DecryptResult(params, sk, encResB64, targetIndex, dbSize, slotsPerRec)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
		elapsedDec := time.Since(startDec).Milliseconds()

		// Total latency
		total := elapsedEnc + elapsedEval + elapsedDec

		// Write to CSV
		w.Write([]string{
			fmt.Sprint(epoch),
			fmt.Sprintf("%d", elapsedEnc),
			fmt.Sprintf("%d", elapsedEval),
			fmt.Sprintf("%d", elapsedDec),
			fmt.Sprintf("%d", total),
		})

		// Log to console
		fmt.Printf("[Epoch %d] Enc=%d ms | Eval=%d ms | Dec=%d ms | Total=%d ms\n",
			epoch, elapsedEnc, elapsedEval, elapsedDec, total)
	}
}
