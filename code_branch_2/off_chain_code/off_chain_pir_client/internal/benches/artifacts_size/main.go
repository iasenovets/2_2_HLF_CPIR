// internal/benches/artifacts_size/main.go
package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"off-chain-pir-client/internal/cpir"
	"off-chain-pir-client/internal/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
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

type channelCfg struct {
	Name         string
	DBSize       int
	MaxJSON      int
	LogN         int
	TargetIndex  int
	LogQiJSON    string
	LogPiJSON    string
	PlaintextMod string
}

var configs = []channelCfg{
	{Name: "mini", DBSize: 64, MaxJSON: 128, LogN: 13, TargetIndex: 13},
	{Name: "mid", DBSize: 73, MaxJSON: 224, LogN: 14, TargetIndex: 13},
	{Name: "rich", DBSize: 128, MaxJSON: 256, LogN: 15, TargetIndex: 13},
}

var (
	outDir = flag.String("out", "plots/artifacts_size/data", "output CSV folder")
)

func main() {
	flag.Parse()
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] cannot create out dir: %v\n", err)
		os.Exit(1)
	}

	for _, cfg := range configs {
		if err := runOne(cfg, *outDir); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] channel=%s: %v\n", cfg.Name, err)
		}
	}
}

func runOne(cfg channelCfg, outDir string) error {
	// 1) InitLedger
	if _, err := utils.Call("InitLedger",
		itoa(cfg.DBSize),
		itoa(cfg.MaxJSON),
		intOrEmpty(cfg.LogN),
		cfg.LogQiJSON,
		cfg.LogPiJSON,
		cfg.PlaintextMod,
	); err != nil {
		return fmt.Errorf("InitLedger: %w", err)
	}

	// 2) GetMetadata
	metaStr, err := utils.Call("GetMetadata")
	if err != nil {
		return fmt.Errorf("GetMetadata: %w", err)
	}
	var meta metaResp
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}
	metadataBytes := len([]byte(metaStr))

	// 3) KeyGen
	params, sk, pk, err := cpir.GenKeysFromMetadata(cpir.Metadata{
		NRecords: meta.NRecords, RecordS: meta.RecordS,
		LogN: meta.LogN, N: meta.N, T: meta.T, LogQi: meta.LogQi, LogPi: meta.LogPi,
	})
	if err != nil {
		return fmt.Errorf("GenKeysFromMetadata: %w", err)
	}
	// serialize keys
	pkBytes, skBytes, err := keySizes(pk, sk)
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}

	// 4) Build query
	qB64, qLen, err := cpir.EncryptQueryBase64(params, pk, cfg.TargetIndex, meta.NRecords, meta.RecordS)
	if err != nil {
		return fmt.Errorf("EncryptQueryBase64: %w", err)
	}
	ctqBytes := qLen // already measured as raw bytes before base64

	// 5) PIRQuery → ct_r
	resB64, err := utils.Call("PIRQuery", qB64)
	if err != nil {
		return fmt.Errorf("PIRQuery: %w", err)
	}
	rawRes, err := base64.StdEncoding.DecodeString(resB64)
	if err != nil {
		return fmt.Errorf("decode ct_r: %w", err)
	}
	ctrBytes := len(rawRes)

	// 6) m_DB size (server helper)
	mdbSizeStr, err := utils.Call("GetMDBSize") // returns integer as string
	if err != nil {
		return fmt.Errorf("GetMDBSize: %w", err)
	}
	mdbBytes, err := strconv.Atoi(mdbSizeStr)
	if err != nil {
		return fmt.Errorf("parse m_DB size: %w", err)
	}

	// 7) Write CSV
	outName := filepath.Join(outDir, fmt.Sprintf("artifacts_%d_%d.csv", meta.LogN, meta.RecordS))
	f, err := os.Create(outName)
	if err != nil {
		return fmt.Errorf("create csv: %w", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{"artifact", "bytes"})
	_ = w.Write([]string{"pk", itoa(pkBytes)})
	_ = w.Write([]string{"sk", itoa(skBytes)})
	_ = w.Write([]string{"ct_q", itoa(ctqBytes)})
	_ = w.Write([]string{"ct_r", itoa(ctrBytes)})
	_ = w.Write([]string{"m_DB", itoa(mdbBytes)})
	_ = w.Write([]string{"metadata_json", itoa(metadataBytes)})

	if err := w.Error(); err != nil {
		return fmt.Errorf("csv write: %w", err)
	}

	fmt.Printf("[OK] wrote %s\n", outName)
	return nil
}

func keySizes(pk *rlwe.PublicKey, sk *rlwe.SecretKey) (int, int, error) {
	var (
		b   []byte
		n   int
		err error
	)
	if b, err = pk.MarshalBinary(); err != nil {
		return 0, 0, err
	}
	n = len(b)
	if b, err = sk.MarshalBinary(); err != nil {
		return 0, 0, err
	}
	return n, len(b), nil
}

func itoa(i int) string { return strconv.Itoa(i) }
func intOrEmpty(v int) string {
	if v <= 0 {
		return ""
	}
	return strconv.Itoa(v)
}

// keep import alive if build tags strip code paths
var _ = errors.New
