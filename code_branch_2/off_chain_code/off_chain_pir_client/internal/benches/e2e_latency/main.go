// internal/benches/e2e_latency/main.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"off-chain-pir-client/internal/cpir"
	"off-chain-pir-client/internal/utils"
)

/*
Figure: End-to-end single-query latency by stage; ct×pt path.
Stages:
  - keygen_ms     : GenKeysFromMetadata
  - enc_ms        : selector build + encode + encrypt
  - eval_ms       : server-side MulNew(ct, m_DB) (if server returns it), else -1
  - dec_ms        : decrypt + decode + window extract

CSV columns: epoch,stage,latency_ms
Filename   : e2elatency_<logN>_<record_s>.csv

Notes:
- Server currently returns only Base64(ct_r). If you add a "PIRQueryTimed"
  method that returns {"b64":"...", "eval_ms":float}, this client will
  auto-detect and use eval_ms. Otherwise it records eval_ms = -1 and you
  can plot eval_rtt_ms separately if desired.
*/

type metaResp struct {
	NRecords int    `json:"n"`
	RecordS  int    `json:"record_s"`
	LogN     int    `json:"logN"`
	N        int    `json:"N"`
	T        uint64 `json:"t"`
	LogQi    []int  `json:"logQi"`
	LogPi    []int  `json:"logPi"`
}

type pirTimedResp struct {
	B64    string  `json:"b64"`
	EvalMS float64 `json:"eval_ms"`
}

type channelCfg struct {
	Name         string
	DBSize       int
	MaxJSON      int
	LogN         int // 13, 14, 15 (0 => auto)
	TargetIndex  int
	LogQiJSON    string // e.g. "[60,60,60,38]" or ""
	LogPiJSON    string // e.g. "[60]" or ""
	PlaintextMod string // e.g. "65537" or ""
}

var configs = []channelCfg{
	{Name: "mini", DBSize: 64, MaxJSON: 128, LogN: 13, TargetIndex: 13},
	{Name: "mid", DBSize: 73, MaxJSON: 224, LogN: 14, TargetIndex: 13},
	{Name: "rich", DBSize: 128, MaxJSON: 256, LogN: 15, TargetIndex: 13},
}

var (
	epochs      = flag.Int("epochs", 20, "number of epochs per channel")
	serverDebug = flag.Bool("debug", false, "print per-epoch debug info")

	// New folder structure for CSV output
	outDir = filepath.Join("plots", "e2elatency", "data")
)

func main() {
	flag.Parse()

	// Ensure output directory exists
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] cannot create output dir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	for _, cfg := range configs {
		if err := runChannel(cfg, *epochs, *serverDebug); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] channel=%s: %v\n", cfg.Name, err)
		}
	}
}

func runChannel(cfg channelCfg, epochs int, verbose bool) error {
	if verbose {
		fmt.Printf("\n[INIT] channel=%s DBSize=%d MaxJSON=%d LogN=%d\n",
			cfg.Name, cfg.DBSize, cfg.MaxJSON, cfg.LogN)
	}

	// --- InitLedger (submit) ---
	_, err := utils.Call("InitLedger",
		fmt.Sprintf("%d", cfg.DBSize),
		fmt.Sprintf("%d", cfg.MaxJSON),
		intOrEmpty(cfg.LogN),
		cfg.LogQiJSON,
		cfg.LogPiJSON,
		cfg.PlaintextMod,
	)
	if err != nil {
		return fmt.Errorf("InitLedger failed: %w", err)
	}

	// --- GetMetadata (evaluate) ---
	metaStr, err := utils.Call("GetMetadata")
	if err != nil {
		return fmt.Errorf("GetMetadata failed: %w", err)
	}
	var meta metaResp
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}
	if verbose {
		fmt.Printf("[META] n=%d s=%d logN=%d N=%d T=%d logQi=%v logPi=%v\n",
			meta.NRecords, meta.RecordS, meta.LogN, meta.N, meta.T, meta.LogQi, meta.LogPi)
	}

	// --- Create CSV inside plots/e2elatency/data/ ---
	outName := filepath.Join(outDir, fmt.Sprintf("e2elatency_%d_%d.csv", meta.LogN, meta.RecordS))
	f, err := os.Create(outName)
	if err != nil {
		return fmt.Errorf("create csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"epoch", "stage", "latency_ms"})

	// --- Benchmark loop ---
	for e := 0; e < epochs; e++ {
		if verbose {
			fmt.Printf("[RUN] epoch=%d\n", e)
		}

		// KeyGen
		t0 := time.Now()
		params, sk, pk, err := cpir.GenKeysFromMetadata(cpir.Metadata{
			NRecords: meta.NRecords, RecordS: meta.RecordS,
			LogN: meta.LogN, N: meta.N, T: meta.T, LogQi: meta.LogQi, LogPi: meta.LogPi,
		})
		if err != nil {
			return fmt.Errorf("GenKeysFromMetadata: %w", err)
		}
		keygenMS := msSince(t0)
		_ = w.Write([]string{itoa(e), "keygen_ms", fmt.Sprintf("%.3f", keygenMS)})

		// Enc
		t1 := time.Now()
		queryB64, _, err := cpir.EncryptQueryBase64(params, pk, cfg.TargetIndex, meta.NRecords, meta.RecordS)
		if err != nil {
			return fmt.Errorf("EncryptQueryBase64: %w", err)
		}
		encMS := msSince(t1)
		_ = w.Write([]string{itoa(e), "enc_ms", fmt.Sprintf("%.3f", encMS)})

		// Eval (server)
		evalMS, rttMS, respB64, err := callPIRWithEvalMS(queryB64)
		if err != nil {
			return fmt.Errorf("PIRQuery: %w", err)
		}
		if evalMS >= 0 {
			_ = w.Write([]string{itoa(e), "eval_ms", fmt.Sprintf("%.3f", evalMS)})
		} else {
			_ = w.Write([]string{itoa(e), "eval_rtt_ms", fmt.Sprintf("%.3f", rttMS)})
		}

		// Dec
		t3 := time.Now()
		if _, err := cpir.DecryptResult(params, sk, respB64, cfg.TargetIndex, meta.NRecords, meta.RecordS); err != nil {
			return fmt.Errorf("DecryptResult: %w", err)
		}
		decMS := msSince(t3)
		_ = w.Write([]string{itoa(e), "dec_ms", fmt.Sprintf("%.3f", decMS)})

		w.Flush()
		if err := w.Error(); err != nil {
			return fmt.Errorf("csv write: %w", err)
		}
	}

	fmt.Printf("[OK] wrote %s\n", outName)
	return nil
}

func callPIRWithEvalMS(encQueryB64 string) (evalMS float64, rttMS float64, resB64 string, err error) {
	resp, callErr := utils.Call("PIRQueryTimed", encQueryB64)
	if callErr == nil {
		var timed pirTimedResp
		if json.Unmarshal([]byte(resp), &timed) == nil && timed.B64 != "" {
			return timed.EvalMS, 0.0, timed.B64, nil
		}
	}

	// fallback
	t := time.Now()
	b64, callErr2 := utils.Call("PIRQuery", encQueryB64)
	rtt := msSince(t)
	if callErr2 != nil {
		return -1, 0, "", callErr2
	}
	return -1, rtt, b64, nil
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Nanoseconds()) / 1e6 }
func itoa(i int) string           { return strconv.Itoa(i) }
func intOrEmpty(v int) string {
	if v <= 0 {
		return ""
	}
	return strconv.Itoa(v)
}

// keep import
var _ = errors.New
