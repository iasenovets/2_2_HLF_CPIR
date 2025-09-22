package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type response struct {
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
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

func WriteOK(w http.ResponseWriter, resp string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response{Response: resp})
}
func WriteErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response{Error: err.Error()})
}

/********* ИНИЦИАЛИЗАЦИЯ HE PARAMS *****************************************/
func CreateParams(logN int) (bgv.Parameters, error) {
	if logN < 13 || logN > 15 {
		return bgv.Parameters{}, fmt.Errorf("LogN must be between 13 and 15")
	}
	paramsLit := bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             []int{54},
		LogP:             []int{54},
		PlaintextModulus: 65537,
	}
	return bgv.NewParametersFromLiteral(paramsLit)
}
