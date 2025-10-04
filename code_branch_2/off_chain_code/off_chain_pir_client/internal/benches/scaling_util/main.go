// internal/benches/scaling_util/main.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"off-chain-pir-client/internal/utils"
)

type metaResp struct {
	NRecords int    `json:"n"`
	RecordS  int    `json:"record_s"`
	LogN     int    `json:"logN"`
	N        int    `json:"N"`
	T        uint64 `json:"t"`
	LogQi    []int  `json:"logQi"`
	LogPi    []int  `json:"logPi"`
}

var outCSV = flag.String("out", "plots/scaling_util/data/scaling_util.csv", "output CSV path")

func main() {
	flag.Parse()

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(*outCSV), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(*outCSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create csv: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"logN", "target_record_s", "actual_record_s", "n", "N",
		"utilization", // u = (n * actual_record_s) / N
	})

	logNs := []int{13, 14, 15}
	slotWindows := []int{64, 128, 224, 256, 384, 512}

	for _, logN := range logNs {
		for _, sTarget := range slotWindows {
			Nguess := 1 << logN
			nGuess := Nguess / sTarget
			if nGuess < 1 {
				nGuess = 1
			}

			// Force logN; let server round record_s if needed.
			if _, err := utils.Call(
				"InitLedger",
				fmt.Sprintf("%d", nGuess),  // n
				fmt.Sprintf("%d", sTarget), // maxJSON ~ desired record_s
				fmt.Sprintf("%d", logN),    // logN
				"", "", "65537",            // logQi, logPi, T
			); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] InitLedger(logN=%d, s=%d): %v\n", logN, sTarget, err)
				continue
			}

			metaStr, err := utils.Call("GetMetadata")
			if err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] GetMetadata: %v\n", err)
				continue
			}
			var m metaResp
			if err := json.Unmarshal([]byte(metaStr), &m); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] parse metadata: %v\n", err)
				continue
			}

			util := float64(m.NRecords*m.RecordS) / float64(m.N)

			_ = w.Write([]string{
				itoa(m.LogN),
				itoa(sTarget),
				itoa(m.RecordS),
				itoa(m.NRecords),
				itoa(m.N),
				fmt.Sprintf("%.6f", util),
			})
			w.Flush()
		}
	}
	fmt.Printf("[OK] wrote %s\n", *outCSV)
}

func itoa(i int) string { return strconv.Itoa(i) }
