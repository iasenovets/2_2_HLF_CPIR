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
// pirTimedResp defines the JSON structure returned by PIRQueryTimed.
type pirTimedResp struct {
	EvalMS float64 `json:"eval_ms"`
	B64    string  `json:"b64"`
}

type request struct {
	Method string   `json:"method"`
	Args   []string `json:"args"`
}

/********* Ledger's World State ***********************/
type LedgerState struct {
	mtx sync.RWMutex
	// Cryptographic context
	params bgv.Parameters  // in-memory BGV params
	m_DB   *rlwe.Plaintext // in-memory plaintext poly

	// Database meta
	nRecords    int      // world state: "n"
	slotsPerRec int      // world state: "record_s"
	records     [][]byte // world state: "record%03d" keys
}

/********* ХЭНДЛЕР INVOKE ******************************************/
func (ls *LedgerState) invoke(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErr(w, err)
		return
	}

	switch req.Method {
	case "InitLedger":
		if len(req.Args) < 2 {
			utils.WriteErr(w, fmt.Errorf("InitLedger requires at least 2 arguments: numRecords, maxJsonLength; optionally: logN, logQi(json), logPi(json), t"))
			return
		}

		n, err1 := strconv.Atoi(req.Args[0])
		maxJSON, err2 := strconv.Atoi(req.Args[1])
		if err1 != nil || err2 != nil || n <= 0 || maxJSON <= 0 {
			utils.WriteErr(w, fmt.Errorf("numRecords and maxJsonLength must be positive integers"))
			return
		}

		// optional: logN (empty/0 means: auto-select)
		var logN int
		if len(req.Args) >= 3 && req.Args[2] != "" {
			if v, err := strconv.Atoi(req.Args[2]); err == nil {
				logN = v
			}
		}

		// optional: logQi, logPi as JSON arrays of ints
		var logQi, logPi []int
		if len(req.Args) >= 4 && req.Args[3] != "" {
			if err := json.Unmarshal([]byte(req.Args[3]), &logQi); err != nil {
				utils.WriteErr(w, fmt.Errorf("invalid logQi JSON: %w", err))
				return
			}
		}
		if len(req.Args) >= 5 && req.Args[4] != "" {
			if err := json.Unmarshal([]byte(req.Args[4]), &logPi); err != nil {
				utils.WriteErr(w, fmt.Errorf("invalid logPi JSON: %w", err))
				return
			}
		}

		// optional: t (plaintext modulus)
		var t uint64 = 65537
		if len(req.Args) >= 6 && req.Args[5] != "" {
			if parsedT, err := strconv.ParseUint(req.Args[5], 10, 64); err == nil && parsedT > 0 {
				t = parsedT
			}
		}

		if err := ls.initLedger(n, maxJSON, logN, logQi, logPi, t); err != nil {
			log.Printf("[ERROR] InitLedger: %v", err)
			utils.WriteErr(w, err)
			return
		}

		utils.WriteOK(w, fmt.Sprintf(
			"ledger initialized with %d records, LogN=%d, slotsPerRec=%d",
			ls.nRecords, ls.params.LogN(), ls.slotsPerRec,
		))

	case "GetMetadata":
		ls.getMetadata(w)

	case "PIRQuery":
		if len(req.Args) != 1 {
			utils.WriteErr(w, fmt.Errorf("need encQueryB64"))
			return
		}
		outB64, err := ls.pirQuery(req.Args[0])
		if err != nil {
			utils.WriteErr(w, err)
			return
		}
		utils.WriteOK(w, outB64)

	case "PIRQueryTimed":
		if len(req.Args) != 1 {
			utils.WriteErr(w, fmt.Errorf("need encQueryB64"))
			return
		}
		outJSON, err := ls.pirQueryTimed(req.Args[0])
		if err != nil {
			utils.WriteErr(w, err)
			return
		}
		utils.WriteOK(w, outJSON)

	// helper cases
	case "PublicQuery":
		if len(req.Args) != 1 {
			utils.WriteErr(w, fmt.Errorf("arg 0 = key (e.g., record000)"))
			return
		}
		ls.publicQuery(w, req.Args[0])

	case "GetMDBSize":
		// returns the serialized size (bytes) of plaintext m_DB
		ls.mtx.RLock()
		if ls.m_DB == nil {
			ls.mtx.RUnlock()
			utils.WriteErr(w, fmt.Errorf("m_DB not initialized"))
			return
		}
		pt := ls.m_DB
		ls.mtx.RUnlock()

		data, err := pt.MarshalBinary()
		if err != nil {
			utils.WriteErr(w, fmt.Errorf("marshal m_DB: %w", err))
			return
		}
		utils.WriteOK(w, fmt.Sprintf("%d", len(data)))

	default:
		utils.WriteErr(w, fmt.Errorf("unknown method"))
	}
}

func (ls *LedgerState) initLedger(n, maxJSON, logN int, logQi, logPi []int, t uint64) error {
	ls.mtx.Lock()
	defer ls.mtx.Unlock()

	// ---- Fallback: choose smallest feasible logN if not provided or <= 0
	// s_guess = ceil(maxJSON/8)*8 (1 byte/slot packing)
	sGuess := ((maxJSON + 7) / 8) * 8
	if logN <= 0 {
		chosen, err := utils.ChooseLogN(n, sGuess)
		if err != nil {
			return fmt.Errorf("auto-select logN failed: %w", err)
		}
		logN = chosen
		log.Printf("[INFO] Auto-selected LogN=%d using n=%d and s_guess=%d", logN, n, sGuess)
	}

	// 1) ---- Build BGV params from hint (defaults applied inside utils)
	hint := utils.BGVParamHint{
		LogN:  logN,
		LogQi: logQi,
		LogPi: logPi,
		T:     t,
	}
	p, err := utils.BuildParamsFromHint(hint)
	if err != nil {
		return fmt.Errorf("failed to set params: %w", err)
	}
	ls.params = p
	log.Printf("[INFO] Params: LogN=%d N=%d |Q|=%d |P|=%d T=%d",
		p.LogN(), p.N(), len(p.Q()), len(p.P()), p.PlaintextModulus())

	// 2) ---- Generate synthetic records (uses logN to pick template)
	gen, err := gen_records.GenerateRecords(n, logN, maxJSON)
	if err != nil {
		return err
	}
	ls.records = gen
	ls.nRecords = len(ls.records)

	// 3) ---- Compute slots per record from actual JSON lengths
	ls.slotsPerRec = utils.CalcSlotsPerRec(ls.records)

	// 4) ---- Final capacity check with actual s
	required := ls.nRecords * ls.slotsPerRec
	if required > ls.params.MaxSlots() {
		return fmt.Errorf("capacity exceeded: required=%d (n=%d × s=%d) > N=%d; try larger logN or smaller records",
			required, ls.nRecords, ls.slotsPerRec, ls.params.MaxSlots())
	}

	// 5) ---- Pack records into plaintext vector
	packed := make([]uint64, ls.params.MaxSlots())
	for recIdx, recBytes := range ls.records {
		start := recIdx * ls.slotsPerRec
		end := start + ls.slotsPerRec
		if end > len(packed) {
			break
		}
		for i := 0; i < len(recBytes) && i < ls.slotsPerRec; i++ {
			packed[start+i] = uint64(recBytes[i])
		}

		// Debug for first 3 and last 3 records only
		if recIdx < 3 || recIdx >= len(ls.records)-3 {
			log.Printf("[DBG] Packed record[%d]: slots [%d:%d) → first 16 values: %v",
				recIdx, start, end, packed[start:start+16])
		}
	}

	// Utilization summary
	filled := 0
	for _, v := range packed {
		if v != 0 {
			filled++
		}
	}
	allocStart := 0
	allocEnd := ls.nRecords * ls.slotsPerRec
	if allocEnd > len(packed) {
		allocEnd = len(packed)
	}
	allocated := allocEnd - allocStart
	empty := len(packed) - allocated
	util := float64(filled) / float64(len(packed)) * 100
	log.Printf("[INFO] Active slots (data) = %d", filled)
	log.Printf("[INFO] Allocated range = [%d:%d) (Allocated slots = %d)", allocStart, allocEnd, allocated)
	log.Printf("[INFO] Empty slots = %d", empty)
	log.Printf("[INFO] Utilization (data/full) = %.2f%%", util)

	// 6) ---- Encode m_DB as plaintext polynomial
	enc := bgv.NewEncoder(ls.params)
	pt := bgv.NewPlaintext(ls.params, ls.params.MaxLevel())
	if err := enc.Encode(packed, pt); err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}
	ls.m_DB = pt

	// Meta parity (debug)
	log.Printf("[META] n=%d, record_s=%d, LogN=%d, N=%d, T=%d, LogQi=%v, LogPi=%v",
		ls.nRecords, ls.slotsPerRec, ls.params.LogN(), ls.params.N(),
		ls.params.PlaintextModulus(), ls.params.LogQi(), ls.params.LogPi())

	return nil
}

// pirQuery performs the core PIR evaluation step inside the chaincode.
// It takes an encrypted one-hot query vector (Base64-encoded) and returns
// an encrypted response containing the selected record, also Base64-encoded.
//
// Steps:
// 1. Decode the Base64 query into ciphertext.
// 2. Perform homomorphic element-wise multiplication with the packed m_DB.
// 3. Serialize the result back to Base64 for transmission to the client.

// --- Methods moved out of invoke ----------------------------------

func (ls *LedgerState) getMetadata(w http.ResponseWriter) {
	ls.mtx.RLock()
	defer ls.mtx.RUnlock()

	meta := struct {
		NRecords int    `json:"n"`
		RecordS  int    `json:"record_s"`
		LogN     int    `json:"logN"`
		N        int    `json:"N"`
		T        uint64 `json:"t"`
		LogQi    []int  `json:"logQi"`
		LogPi    []int  `json:"logPi"`
	}{
		NRecords: ls.nRecords,
		RecordS:  ls.slotsPerRec,
		LogN:     ls.params.LogN(),
		N:        ls.params.N(),
		T:        ls.params.PlaintextModulus(),
		LogQi:    ls.params.LogQi(),
		LogPi:    ls.params.LogPi(),
	}

	out, err := json.Marshal(meta)
	if err != nil {
		utils.WriteErr(w, fmt.Errorf("failed to marshal metadata: %w", err))
		return
	}
	utils.WriteOK(w, string(out))
}

func (ls *LedgerState) pirQuery(encQueryB64 string) (string, error) {
	ls.mtx.RLock()
	defer ls.mtx.RUnlock()

	if ls.m_DB == nil {
		return "", fmt.Errorf("PIR database not initialized")
	}

	// 1. Decode Base64 query into ciphertext
	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 query: %w", err)
	}

	ctQuery := rlwe.NewCiphertext(ls.params, 1, ls.params.MaxLevel())
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", fmt.Errorf("failed to unmarshal query ciphertext: %w", err)
	}

	// Debug print: input ciphertext size in bytes
	log.Printf("[EVAL] Query ciphertext size = %d bytes", len(encBytes))

	// 2. Perform homomorphic multiplication (ciphertext × plaintext)
	eval := bgv.NewEvaluator(ls.params, nil)

	start := time.Now()
	ctRes, err := eval.MulNew(ctQuery, ls.m_DB)
	if err != nil {
		return "", fmt.Errorf("PIR evaluation failed: %w", err)
	}
	evalDuration := time.Since(start)

	// Debug: print timing and ring info
	log.Printf("[EVAL] PIR evaluation completed in %.3f ms (LogN=%d, ring slots=%d)",
		float64(evalDuration.Nanoseconds())/1e6, ls.params.LogN(), ls.params.MaxSlots())

	// 3. Serialize result back to Base64
	outBytes, err := ctRes.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal result ciphertext: %w", err)
	}

	// Debug: output ciphertext size
	log.Printf("[EVAL] Result ciphertext size = %d bytes", len(outBytes))

	return base64.StdEncoding.EncodeToString(outBytes), nil
}

// pirQueryTimed runs PIR evaluation and returns timing + ciphertext.
// pirQueryTimed performs the same PIR evaluation as pirQuery()
// but returns a JSON object with the Base64 ciphertext and internal Eval time in ms.
func (ls *LedgerState) pirQueryTimed(encQueryB64 string) (string, error) {
	ls.mtx.RLock()
	defer ls.mtx.RUnlock()

	if ls.m_DB == nil {
		return "", fmt.Errorf("PIR database not initialized")
	}

	// Decode input ciphertext
	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 query: %w", err)
	}

	ctQuery := rlwe.NewCiphertext(ls.params, 1, ls.params.MaxLevel())
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", fmt.Errorf("failed to unmarshal ciphertext: %w", err)
	}

	// Perform homomorphic multiplication (ct × pt)
	eval := bgv.NewEvaluator(ls.params, nil)
	start := time.Now()
	ctRes, err := eval.MulNew(ctQuery, ls.m_DB)
	if err != nil {
		return "", fmt.Errorf("PIR evaluation failed: %w", err)
	}
	evalMS := float64(time.Since(start).Nanoseconds()) / 1e6 // ms

	// Serialize result
	outBytes, err := ctRes.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal result ciphertext: %w", err)
	}

	outB64 := base64.StdEncoding.EncodeToString(outBytes)

	// Compose JSON
	payload := map[string]interface{}{
		"b64":     outB64,
		"eval_ms": evalMS,
	}
	outJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PIRQueryTimed response: %w", err)
	}

	log.Printf("[EVAL_TIMED] Eval completed in %.3f ms (LogN=%d, N=%d)", evalMS, ls.params.LogN(), ls.params.N())

	return string(outJSON), nil
}

func (ls *LedgerState) publicQuery(w http.ResponseWriter, key string) {
	idx, err := strconv.Atoi(key[len(key)-3:])
	if err != nil || idx < 0 {
		utils.WriteErr(w, fmt.Errorf("invalid record index from key %q", key))
		return
	}

	ls.mtx.RLock()
	defer ls.mtx.RUnlock()
	if idx >= len(ls.records) {
		utils.WriteErr(w, fmt.Errorf("not found"))
		return
	}
	utils.WriteOK(w, string(ls.records[idx]))
}

/********* MAIN ***************************************************/
func main() {
	ls := &LedgerState{}
	http.HandleFunc("/invoke", ls.invoke)
	log.Println("REST chaincode listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
