package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

var Debug = true

type response struct {
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Metadata mirrors the server's GetMetadata response.
type Metadata struct {
	NRecords int    `json:"n"`
	RecordS  int    `json:"record_s"`
	LogN     int    `json:"logN"`
	N        int    `json:"N"`
	T        uint64 `json:"t"`
	LogQi    []int  `json:"logQi"`
	LogPi    []int  `json:"logPi"`
}

// BGVParamHint: optional inputs for building bgv.Parameters.
// Any empty field falls back to a sensible default.
type BGVParamHint struct {
	LogN  int
	LogQi []int
	LogPi []int
	T     uint64
}

// BuildParamsFromHint builds bgv.Parameters from the hint,
// applying defaults where the hint omits values.
func BuildParamsFromHint(h BGVParamHint) (bgv.Parameters, error) {
	if h.LogN <= 0 {
		return bgv.Parameters{}, fmt.Errorf("LogN must be set (>0) in BGVParamHint")
	}
	lit := bgv.ParametersLiteral{
		LogN:             h.LogN,
		PlaintextModulus: h.T,
	}
	if lit.PlaintextModulus == 0 {
		lit.PlaintextModulus = 65537
	}
	if len(h.LogQi) > 0 {
		lit.LogQ = h.LogQi
	} else {
		lit.LogQ = []int{54}
	}
	if len(h.LogPi) > 0 {
		lit.LogP = h.LogPi
	} else {
		lit.LogP = []int{54}
	}
	return bgv.NewParametersFromLiteral(lit)
}

// BuildParamsFromMetadata convenience: converts Metadata -> BGVParamHint -> bgv.Parameters.
func BuildParamsFromMetadata(m Metadata) (bgv.Parameters, error) {
	h := BGVParamHint{
		LogN:  m.LogN,
		LogQi: m.LogQi,
		LogPi: m.LogPi,
		T:     m.T,
	}
	return BuildParamsFromHint(h)
}

// (Optional) legacy helper kept for compatibility.
func ParamsLiteral128(logN int) (bgv.Parameters, error) {
	return BuildParamsFromHint(BGVParamHint{LogN: logN})
}

// ChooseLogN selects the smallest feasible logN such that
// n * slotsPerRec <= 2^logN. Returns error if no feasible logN found.
func ChooseLogN(n int, slotsPerRec int) (int, error) {
	if n <= 0 || slotsPerRec <= 0 {
		return 0, fmt.Errorf("invalid inputs: n=%d, slotsPerRec=%d", n, slotsPerRec)
	}
	const (
		MinLogN = 13
		MaxLogN = 15
	)

	requiredSlots := n * slotsPerRec
	for logN := MinLogN; logN <= MaxLogN; logN++ {
		if requiredSlots <= (1 << logN) {
			log.Printf("[INFO] ChooseLogN: requiredSlots=%d, selected logN=%d (N=%d)",
				requiredSlots, logN, 1<<logN)
			return logN, nil
		}
	}
	return 0, fmt.Errorf("cannot fit DB: requiredSlots=%d exceeds max supported N=%d",
		requiredSlots, 1<<MaxLogN)
}

// CalcSlotsPerRec calculates slots per record based on the actual records
func CalcSlotsPerRec(records [][]byte) int {
	max := 0
	for _, recBytes := range records {
		if len(recBytes) > max {
			max = len(recBytes)
		}
	}
	slotsPerRec := ((max + 7) / 8) * 8
	if slotsPerRec == 0 {
		slotsPerRec = 8
	}

	log.Printf("[DEBUG] Max actual JSON len = %d bytes", max)
	log.Printf("[DEBUG] slotsPerRec calculated = %d  ( = %d × 8-byte blocks)",
		slotsPerRec, slotsPerRec/8)

	return slotsPerRec
}

/********* UTILS *************************************************/
func ShouldPrintDebug(i, total int) bool {
	// Print first 3 and last 3 records
	return i < 3 || i >= total-3
}

func FakeHash(prefix string, i int, length int) string {
	if length <= 0 {
		return ""
	}
	base := prefix + strconv.Itoa(i)
	hash := sha256.Sum256([]byte(base))
	hexStr := hex.EncodeToString(hash[:])

	for len(hexStr) < length {
		base += "x"
		h := sha256.Sum256([]byte(base))
		hexStr += hex.EncodeToString(h[:])
	}
	return hexStr[:length]
}

// DebugPrintRecords prints debug information about the plaintext database
func DebugPrintRecords(params bgv.Parameters, records [][]byte, slotsPerRec int, pt *rlwe.Plaintext) {
	if pt == nil {
		return
	}

	enc := bgv.NewEncoder(params)
	vec := make([]uint64, params.MaxSlots())
	if err := enc.Decode(pt, vec); err != nil {
		log.Println("[ERROR] decode error in debugPrintRecords:", err)
		return
	}

	totalRecs := len(records)
	log.Printf("[INFO] Debugging PTDB: total records = %d, slotsPerRec = %d", totalRecs, slotsPerRec)
	log.Println("--- BEGIN DEBUG DB CONTENT ---")

	// Helper to decode a single record
	printRecord := func(idx int) {
		start := idx * slotsPerRec
		end := start + slotsPerRec
		if start >= len(vec) {
			return
		}
		if end > len(vec) {
			end = len(vec)
		}

		var buf []byte
		for _, v := range vec[start:end] {
			if v == 0 {
				break
			}
			buf = append(buf, byte(v))
		}
		log.Printf("[DEBUG rec %03d | slots %d–%d] %s", idx, start, end-1, string(buf))
	}

	// Print first 3 records
	for i := 0; i < 3 && i < totalRecs; i++ {
		printRecord(i)
	}

	// Separator if there are many records
	if totalRecs > 6 {
		log.Println("... (skipping middle records) ...")
	}

	// Print last 3 records
	for i := totalRecs - 3; i < totalRecs; i++ {
		if i >= 3 { // Avoid duplicates for small DB sizes
			printRecord(i)
		}
	}

	log.Println("--- END DEBUG DB CONTENT ---")
}

// parseRecordIndex extracts the numeric index from keys like "record013" → 13.
// Returns (idx, true) on success, or (0, false) if the key doesn't match.
func ParseRecordIndex(key string) (int, bool) {
	const pfx = "record"
	if !strings.HasPrefix(key, pfx) {
		return 0, false
	}
	s := key[len(pfx):]
	idx, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return idx, true
}

// hexHead returns up to the first n bytes of b as a hex string (no "0x"),
// with "..." suffix if truncated.
func HexHead(b []byte, n int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) <= n {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:n]) + "..."
}

func WriteOK(w http.ResponseWriter, resp string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response{Response: resp})
}
func WriteErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response{Error: err.Error()})
}
