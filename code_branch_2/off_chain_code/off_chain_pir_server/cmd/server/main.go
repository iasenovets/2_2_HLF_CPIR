package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	"off-chain-pir-server/internal/gen_records"
	"off-chain-pir-server/internal/utils"
)

/********* МОДЕЛИ *************************************************/

type request struct {
	Method string   `json:"method"`
	Args   []string `json:"args"`
}

/********* Ledger's World State ***********************/
var (
	mtx         sync.RWMutex
	params      bgv.Parameters
	ptdb        *rlwe.Plaintext
	records     [][]byte
	slotsPerRec int
)

/********* ХЭНДЛЕР INVOKE ******************************************/
func invoke(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErr(w, err)
		return
	}

	switch req.Method {
	case "InitLedger":
		if len(req.Args) != 3 {
			utils.WriteErr(w, fmt.Errorf("InitLedger requires exactly 3 arguments: numRecords, maxJsonLength, logN"))
			return
		}

		n, err1 := strconv.Atoi(req.Args[0])
		maxJsonLength, err2 := strconv.Atoi(req.Args[1])
		logN, err3 := strconv.Atoi(req.Args[2])

		if err1 != nil || err2 != nil || err3 != nil || n <= 0 || maxJsonLength <= 0 || logN <= 0 {
			utils.WriteErr(w, fmt.Errorf("numRecords, maxJsonLength and logN must be positive integers"))
			return
		}

		err := initLedger(n, maxJsonLength, logN)
		if err != nil {
			log.Printf("[ERROR] Failed to init ledger from invoke: %v", err)
			utils.WriteErr(w, err)
			return
		}
		utils.WriteOK(w, fmt.Sprintf("ledger initialized with %d records, LogN=%d, slotsPerRec=%d", n, logN, slotsPerRec))

	case "GetSlotsPerRecord":
		utils.WriteOK(w, fmt.Sprintf("%d", slotsPerRec))

	case "PublicQueryCTI":
		if len(req.Args) != 1 {
			utils.WriteErr(w, fmt.Errorf("arg 0 = key (e.g., record000)"))
			return
		}
		key := req.Args[0]
		idx, err := strconv.Atoi(key[len(key)-3:])
		if err != nil || idx < 0 {
			utils.WriteErr(w, fmt.Errorf("invalid record index from key %s", key))
			return
		}

		mtx.RLock()
		defer mtx.RUnlock()
		if idx >= len(records) {
			utils.WriteErr(w, fmt.Errorf("not found"))
			return
		}
		utils.WriteOK(w, string(records[idx]))

	case "PublicQueryALL":
		mtx.RLock()
		defer mtx.RUnlock()
		utils.WriteOK(w, fmt.Sprintf("%d", len(records)))

	case "PIRQuery":
		if len(req.Args) != 1 {
			utils.WriteErr(w, fmt.Errorf("need encQueryB64"))
			return
		}
		outB64, err := pirQuery(req.Args[0])
		if err != nil {
			utils.WriteErr(w, err)
			return
		}
		utils.WriteOK(w, outB64)

	default:
		utils.WriteErr(w, fmt.Errorf("unknown method"))
	}
}

/********* БИЗНЕС-ЛОГИКА ******************************************/
func initLedger(n int, maxJsonLength int, logN int) error {
	mtx.Lock()
	defer mtx.Unlock()

	// 1. Create BGV parameters
	p, err := utils.CreateParams(logN)
	if err != nil {
		return err
	}
	params = p
	log.Printf("[INFO] Initializing ledger with LogN=%d (Ring size = %d slots)", logN, params.MaxSlots())

	// Determine channel based on logN
	channel := fmt.Sprintf("channel_logN%d", logN)

	// 2. Generate synthetic records
	genRecords, err := gen_records.GenerateRecords(n, logN, maxJsonLength)
	if err != nil {
		return err
	}
	records = genRecords
	log.Printf("[INFO] Generated %d records for channel=%s, maxJsonLength=%d", len(records), channel, maxJsonLength)

	// Print sample record info
	if len(records) > 0 {
		log.Printf("[DEBUG] Sample record[0]: JSON length = %d bytes, content = %s",
			len(records[0]), string(records[0]))
	}

	// 3. Calculate slots per record
	slotsPerRec = utils.CalcSlotsPerRec(records)
	log.Printf("[INFO] slotsPerRec auto-set = %d", slotsPerRec)

	// 4. Validate ring capacity
	requiredSlots := len(records) * slotsPerRec
	availableSlots := params.MaxSlots()
	log.Printf("[DEBUG] Ring size check: Required slots = %d (%d records * %d slots/rec), Available slots = %d",
		requiredSlots, len(records), slotsPerRec, availableSlots)

	if requiredSlots > availableSlots {
		err := fmt.Errorf("DB too big for chosen ring. Required slots: %d, available: %d", requiredSlots, availableSlots)
		log.Printf("[ERROR] %v", err)
		return err
	}

	// 5. Pack records into plaintext vector
	packed := make([]uint64, params.MaxSlots())
	for recIdx, recBytes := range records {
		start := recIdx * slotsPerRec
		end := start + slotsPerRec
		if end > len(packed) {
			break
		}

		for i := 0; i < len(recBytes) && i < slotsPerRec; i++ {
			packed[start+i] = uint64(recBytes[i])
		}

		// Debug for first 3 and last 3 records only
		if recIdx < 3 || recIdx >= len(records)-3 {
			log.Printf("[DBG] Packed record[%d]: slots [%d:%d) → first 16 values: %v",
				recIdx, start, end, packed[start:start+16])
		}
	}

	// Print packed array summary with utilization details
	filledSlots := 0
	for _, v := range packed {
		if v != 0 {
			filledSlots++
		}
	}

	allocatedRangeStart := 0
	allocatedRangeEnd := len(records) * slotsPerRec
	if allocatedRangeEnd > len(packed) {
		allocatedRangeEnd = len(packed)
	}

	allocatedSlots := allocatedRangeEnd - allocatedRangeStart
	emptySlots := len(packed) - allocatedSlots
	utilization := float64(filledSlots) / float64(len(packed)) * 100

	log.Printf("[INFO] Active slots (data) = %d", filledSlots)
	log.Printf("[INFO] Allocated range = [%d:%d) (Allocated slots = %d)", allocatedRangeStart, allocatedRangeEnd, allocatedSlots)
	log.Printf("[INFO] Empty slots = %d", emptySlots)
	log.Printf("[INFO] Utilization (data/full) = %.2f%%", utilization)

	// 6. Encode PTDB
	enc := bgv.NewEncoder(params)
	pt := bgv.NewPlaintext(params, params.MaxLevel())
	if err := enc.Encode(packed, pt); err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}
	ptdb = pt
	log.Println("[INFO] PTDB ready (encoded)")

	// Optional: debug print for encoded polynomial representation
	utils.DebugPrintRecords(params, records, slotsPerRec, ptdb)
	return nil
}

// pirQuery performs the core PIR evaluation step inside the chaincode.
// It takes an encrypted one-hot query vector (Base64-encoded) and returns
// an encrypted response containing the selected record, also Base64-encoded.
//
// Steps:
// 1. Decode the Base64 query into ciphertext.
// 2. Perform homomorphic element-wise multiplication with the packed PTDB.
// 3. Serialize the result back to Base64 for transmission to the client.

func pirQuery(encQueryB64 string) (string, error) {
	mtx.RLock()
	defer mtx.RUnlock()

	if ptdb == nil {
		return "", fmt.Errorf("PIR database not initialized")
	}

	// 1. Decode Base64 query into ciphertext
	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 query: %w", err)
	}

	ctQuery := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", fmt.Errorf("failed to unmarshal query ciphertext: %w", err)
	}

	// Debug print: input ciphertext size in bytes
	log.Printf("[EVAL] Query ciphertext size = %d bytes", len(encBytes))

	// 2. Perform homomorphic multiplication (ciphertext × plaintext)
	eval := bgv.NewEvaluator(params, nil)

	start := time.Now()
	ctRes, err := eval.MulNew(ctQuery, ptdb)
	if err != nil {
		return "", fmt.Errorf("PIR evaluation failed: %w", err)
	}
	evalDuration := time.Since(start)

	// Debug: print timing and ring info
	log.Printf("[EVAL] PIR evaluation completed in %.3f ms (LogN=%d, ring slots=%d)",
		float64(evalDuration.Nanoseconds())/1e6, params.LogN(), params.MaxSlots())

	// 3. Serialize result back to Base64
	outBytes, err := ctRes.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal result ciphertext: %w", err)
	}

	// Debug: output ciphertext size
	log.Printf("[EVAL] Result ciphertext size = %d bytes", len(outBytes))

	return base64.StdEncoding.EncodeToString(outBytes), nil
}

/********* MAIN ***************************************************/
func main() {
	http.HandleFunc("/invoke", invoke)
	log.Println("REST chaincode listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
