// pir_mini_chaincode.go
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"on_chain_pir_server/internal/gen_records"
	"on_chain_pir_server/internal/precomputed" // <— add this
	"on_chain_pir_server/internal/utils"
	"time"

	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

/**************  GLOBAL DEBUG SWITCH  *********************************/
var Debug = true

func dbg(format string, a ...interface{}) {
	if Debug {
		fmt.Printf(format+"\n", a...)
	}
}

/**************  CHAINCODE STRUCT **************************************/
type PIRChainCode struct {
	contractapi.Contract

	// Cryptographic context
	Params bgv.Parameters  // in-memory BGV params
	m_DB   *rlwe.Plaintext // in-memory plaintext poly

	// Metadata (mirror world state keys)
	NRecords    int // world state: "n"
	SlotsPerRec int // world state: "record_s"

	// Optional cache of JSON records (not required for PIR path)
	Records [][]byte // world state: "record%03d" keys

	initialized bool
}

/**************  INIT LEDGER *******************************************/
func (cc *PIRChainCode) InitLedger(ctx contractapi.TransactionContextInterface,
	numRecordsStr, maxJsonLengthStr string) (string, error) {

	dbg("\n/**************  INIT LEDGER START ****************************************/")
	start := time.Now()

	n, err1 := strconv.Atoi(numRecordsStr)
	maxJSON, err2 := strconv.Atoi(maxJsonLengthStr)
	if err1 != nil || err2 != nil || n <= 0 || maxJSON <= 0 {
		return "", fmt.Errorf("InitLedger: numRecords and maxJsonLength must be positive integers")
	}

	// ---- Optional params: logN, logQi, logPi, t ----
	var logN int
	var logQi, logPi []int
	var t uint64 = 65537

	// ---- Fallback: auto-select logN if missing ----
	sGuess := ((maxJSON + 7) / 8) * 8
	if logN <= 0 {
		chosen, err := utils.ChooseLogN(n, sGuess)
		if err != nil {
			return "", fmt.Errorf("InitLedger: auto-select logN failed: %w", err)
		}
		logN = chosen
		dbg("[INFO] Auto-selected LogN=%d using n=%d, s_guess=%d", logN, n, sGuess)
	}

	// ---- 1) Build params from hint ----
	hint := utils.BGVParamHint{LogN: logN, LogQi: logQi, LogPi: logPi, T: t}
	p, err := utils.BuildParamsFromHint(hint)
	if err != nil {
		return "", fmt.Errorf("InitLedger: failed to set params: %w", err)
	}
	cc.Params = p
	dbg("[INFO] Params: LogN=%d N=%d |Q|=%d |P|=%d T=%d",
		p.LogN(), p.N(), len(p.Q()), len(p.P()), p.PlaintextModulus())

	// ---- 2) Generate synthetic records ----
	dbg("[CC][INIT] Generating synthetic records...")
	records, err := gen_records.GenerateRecords(n, logN, maxJSON)
	if err != nil {
		return "", err
	}
	cc.Records = records
	cc.NRecords = len(records)

	// ---- 3) Store JSON records ----
	dbg("[CC][INIT] Storing JSON records to world state...")
	for i, rec := range cc.Records {
		if err := ctx.GetStub().PutState(fmt.Sprintf("record%03d", i), rec); err != nil {
			return "", err
		}
	}

	// ---- 4) Compute slots per record ----
	cc.SlotsPerRec = utils.CalcSlotsPerRec(cc.Records)

	// ---- 5) Capacity check ----
	required := cc.NRecords * cc.SlotsPerRec
	if required > cc.Params.MaxSlots() {
		return "", fmt.Errorf("capacity exceeded: required=%d > N=%d", required, cc.Params.MaxSlots())
	}

	// ---- 6) Pack → encode into m_DB ----
	dbg("[CC][INIT] Packing and encoding database...")
	packed := make([]uint64, cc.Params.MaxSlots())
	for recIdx, recBytes := range cc.Records {
		start := recIdx * cc.SlotsPerRec
		end := start + cc.SlotsPerRec
		if end > len(packed) {
			break
		}
		for j := 0; j < len(recBytes) && j < cc.SlotsPerRec; j++ {
			packed[start+j] = uint64(recBytes[j])
		}
		if recIdx < 3 || recIdx >= len(cc.Records)-3 {
			dbg("[DBG] Packed record[%d]: slots [%d:%d) → first 16 values: %v",
				recIdx, start, end, packed[start:start+16])
		}
	}

	enc := bgv.NewEncoder(cc.Params)
	pt := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel())
	if err := enc.Encode(packed, pt); err != nil {
		return "", fmt.Errorf("failed to encode DB: %v", err)
	}
	cc.m_DB = pt

	// ---- 7) Persist to world state ----
	dbg("[CC][INIT] Persisting to world state...")
	ptBytes, _ := pt.MarshalBinary()
	if err := ctx.GetStub().PutState("m_DB", ptBytes); err != nil {
		return "", err
	}
	ctx.GetStub().PutState("n", []byte(fmt.Sprintf("%d", cc.NRecords)))
	ctx.GetStub().PutState("record_s", []byte(fmt.Sprintf("%d", cc.SlotsPerRec)))

	paramsMeta := struct {
		LogN  int    `json:"logN"`
		N     int    `json:"N"`
		LogQi []int  `json:"logQi"`
		LogPi []int  `json:"logPi"`
		T     uint64 `json:"t"`
	}{
		LogN:  p.LogN(),
		N:     p.N(),
		LogQi: p.LogQi(),
		LogPi: p.LogPi(),
		T:     p.PlaintextModulus(),
	}
	pm, _ := json.Marshal(paramsMeta)
	ctx.GetStub().PutState("bgv_params", pm)

	// ---- Debug parity log ----
	dbg("[CC][INIT][META] n=%d record_s=%d logN=%d N=%d T=%d logQi=%v logPi=%v",
		cc.NRecords, cc.SlotsPerRec, p.LogN(), p.N(), p.PlaintextModulus(), p.LogQi(), p.LogPi())
	cc.initialized = true

	elapsed := time.Since(start)
	executionTime := float64(elapsed.Nanoseconds()) / 1e6
	dbg("[CC][INIT] Completed in %.3f ms (LogN=%d, slots=%d)",
		executionTime, cc.Params.LogN(), cc.Params.MaxSlots())
	dbg("/**************  INIT LEDGER END ******************************************/")

	// Return execution time as JSON
	result := map[string]interface{}{
		"status":            "success",
		"execution_time_ms": executionTime,
	}
	resultJSON, _ := json.Marshal(result)
	return string(resultJSON), nil
}

/**************  GET METADATA *******************************************/
func (cc *PIRChainCode) GetMetadata(ctx contractapi.TransactionContextInterface) (string, error) {

	dbg("\n/**************  GET METADATA START ************************************/")
	start := time.Now()
	// --- Load n ---
	nBytes, err := ctx.GetStub().GetState("n")
	if err != nil || nBytes == nil {
		return "", fmt.Errorf("[CC][GETMETADATA]: missing n in world state")
	}
	n, _ := strconv.Atoi(string(nBytes))

	// --- Load record_s ---
	sBytes, err := ctx.GetStub().GetState("record_s")
	if err != nil || sBytes == nil {
		return "", fmt.Errorf("[CC][GETMETADATA]: missing record_s in world state")
	}
	recordS, _ := strconv.Atoi(string(sBytes))

	// --- Load bgv_params ---
	paramsBytes, err := ctx.GetStub().GetState("bgv_params")
	if err != nil || paramsBytes == nil {
		return "", fmt.Errorf("[CC][GETMETADATA]: missing bgv_params in world state")
	}
	var paramsMeta struct {
		LogN  int    `json:"logN"`
		N     int    `json:"N"`
		LogQi []int  `json:"logQi"`
		LogPi []int  `json:"logPi"`
		T     uint64 `json:"t"`
	}
	if err := json.Unmarshal(paramsBytes, &paramsMeta); err != nil {
		return "", fmt.Errorf("[CC][GETMETADATA]: failed to parse bgv_params: %w", err)
	}

	// --- Construct metadata blob ---
	meta := struct {
		NRecords int    `json:"n"`
		RecordS  int    `json:"record_s"`
		LogN     int    `json:"logN"`
		N        int    `json:"N"`
		T        uint64 `json:"t"`
		LogQi    []int  `json:"logQi"`
		LogPi    []int  `json:"logPi"`
	}{
		NRecords: n,
		RecordS:  recordS,
		LogN:     paramsMeta.LogN,
		N:        paramsMeta.N,
		T:        paramsMeta.T,
		LogQi:    paramsMeta.LogQi,
		LogPi:    paramsMeta.LogPi,
	}

	out, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("[CC][GETMETADATA]: failed to marshal metadata: %w", err)
	}

	dbg("[CC][GETMETADATA] n=%d record_s=%d | LogN=%d N=%d T=%d | LogQi=%v LogPi=%v",
		meta.NRecords, meta.RecordS, meta.LogN, meta.N, meta.T, meta.LogQi, meta.LogPi)

	elapsed := time.Since(start)
	executionTime := float64(elapsed.Nanoseconds()) / 1e6
	dbg("[CC][GETMETADATA] Completed in %.3f ms", executionTime)
	dbg("/**************  GET METADATA END **************************************/")

	// Return metadata with execution time
	result := map[string]interface{}{
		"metadata":          json.RawMessage(out),
		"execution_time_ms": executionTime,
	}
	resultJSON, _ := json.Marshal(result)
	return string(resultJSON), nil
}

/**************  PUBLIC QUERY *******************************************/
func (cc *PIRChainCode) PublicQuery(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	dbg("\n/**************  PUBLIC QUERY START ****************************************/")

	if key == "" {
		return "", fmt.Errorf("PublicQuery: key must not be empty")
	}

	if idx, ok := utils.ParseRecordIndex(key); ok {
		dbg("[CC][PUBLIC] Retrieving key=%q (index=%d)", key, idx)
	} else {
		dbg("[CC][PUBLIC] Retrieving key=%q (index=unknown)", key)
	}

	// --- Load record from world state ---
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", fmt.Errorf("PublicQuery: ledger read failed: %w", err)
	}
	if b == nil {
		return "", fmt.Errorf("PublicQuery: record %s not found", key)
	}

	dbg("/**************  PUBLIC QUERY END ******************************************/")
	return string(b), nil
}

/**************  PIR QUERY *********************************************/

func (cc *PIRChainCode) PIRQuery(ctx contractapi.TransactionContextInterface, encQueryB64 string) (string, error) {
	dbg("\n/**************  PIR QUERY START ****************************************/")
	start := time.Now()

	if encQueryB64 == "" {
		return "", fmt.Errorf("PIRQuery: empty encQueryB64")
	}
	fmt.Printf("Received encQueryB64 length: %d\n", len(encQueryB64))
	fmt.Printf("First 100 chars: %s\n", encQueryB64[:min(100, len(encQueryB64))])

	// Ensure m_DB is available (reload from ledger if needed)
	if cc.m_DB == nil {
		raw, err := ctx.GetStub().GetState("m_DB")
		if err != nil {
			return "", fmt.Errorf("PIRQuery: failed to read m_DB from ledger: %w", err)
		}
		if raw == nil {
			return "", fmt.Errorf("PIRQuery: m_DB not found in world state")
		}
		pt := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel())
		if err := pt.UnmarshalBinary(raw); err != nil {
			return "", fmt.Errorf("PIRQuery: failed to unmarshal m_DB: %w", err)
		}
		cc.m_DB = pt
		dbg("[CC] PIRQuery: m_DB reloaded (level=%d, N=%d)", cc.Params.MaxLevel(), cc.Params.N())
	}

	// Decode Base64 → ciphertext
	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", fmt.Errorf("PIRQuery: failed to decode base64 query: %w", err)
	}
	{
		// hash + head hex for quick correlation with client logs
		sum := sha256.Sum256(encBytes)
		dbg("[CC][PIR] Decoded query: bytes=%d sha256=%s head32=%s",
			len(encBytes), hex.EncodeToString(sum[:]), utils.HexHead(encBytes, 32))
	}

	ctQuery := rlwe.NewCiphertext(cc.Params, 1, cc.Params.MaxLevel())
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", fmt.Errorf("PIRQuery: failed to unmarshal query ciphertext: %w", err)
	}
	dbg("[CC][PIR] Query ciphertext size = %d bytes", len(encBytes))

	// Homomorphic evaluation: ct × pt
	eval := bgv.NewEvaluator(cc.Params, nil)
	homomorphicStart := time.Now()
	ctRes, err := eval.MulNew(ctQuery, cc.m_DB)
	if err != nil {
		return "", fmt.Errorf("PIRQuery: PIR evaluation failed: %w", err)
	}
	homomorphicElapsed := time.Since(homomorphicStart)
	dbg("[CC][PIR] Homomorphic evaluation completed in %.3f ms", float64(homomorphicElapsed.Nanoseconds())/1e6)

	// Marshal result → Base64
	outBytes, err := ctRes.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("PIRQuery: failed to marshal result ciphertext: %w", err)
	}
	dbg("[CC][PIR] Result ciphertext size = %d bytes", len(outBytes))

	elapsed := time.Since(start)
	dbg("[CC][PIR] Total PIRQuery completed in %.3f ms (HE eval: %.3f ms)",
		float64(elapsed.Nanoseconds())/1e6, float64(homomorphicElapsed.Nanoseconds())/1e6)
	dbg("/**************  PIR QUERY END ******************************************/")

	return base64.StdEncoding.EncodeToString(outBytes), nil
}

// Evaluate-style (no ledger writes) - use this path if you're submitting through cli (peer query ...)
func (cc *PIRChainCode) PIRQueryAuto(ctx contractapi.TransactionContextInterface) (string, error) {
	// Option A: If you maintain an "initialized" flag:
	dbg("\n/**************  PIR QUERY AUTO START ***********************************/")
	start := time.Now()

	if !cc.initialized {
		return "", fmt.Errorf("[CC][PIR_AUTO]: chaincode not initialized - call InitLedger first")
	}

	logN := cc.Params.LogN()
	ctb64, ok := precomputed.B64ForLogN(logN)
	if !ok {
		return "", fmt.Errorf("[CC][PIR_AUTO]: no precomputed ct_q for LogN=%d", logN)
	}
	dbg("[CC][PIR_AUTO] using baked ct_q for LogN=%d (len=%d)", logN, len(ctb64))
	result, _ := cc.PIRQuery(ctx, ctb64)

	elapsed := time.Since(start)
	executionTime := float64(elapsed.Nanoseconds()) / 1e6
	dbg("[CC][PIR_AUTO] Completed in %.3f ms", executionTime)
	dbg("/**************  PIR QUERY AUTO END *************************************/")

	// Return result with execution time
	response := map[string]interface{}{
		"encrypted_result":  result,
		"execution_time_ms": executionTime,
	}
	responseJSON, _ := json.Marshal(response)
	return string(responseJSON), nil
}

// GetStateSize(key) -> int
func (cc *PIRChainCode) GetStateSize(ctx contractapi.TransactionContextInterface, key string) (int, error) {
	val, err := ctx.GetStub().GetState(key)
	if err != nil {
		return 0, err
	}
	return len(val), nil
}

// GetHistoryForKey returns the full modification history of a key as JSON. (useful when reInit)
func (cc *PIRChainCode) GetHistoryForKey(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	historyIter, err := ctx.GetStub().GetHistoryForKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to get history for key %s: %v", key, err)
	}
	defer historyIter.Close()

	var records []map[string]interface{}

	for historyIter.HasNext() {
		mod, err := historyIter.Next()
		if err != nil {
			return "", fmt.Errorf("error iterating history: %v", err)
		}

		record := map[string]interface{}{
			"tx_id":        mod.TxId,
			"is_delete":    mod.IsDelete,
			"timestamp":    mod.Timestamp.AsTime().UTC().Format(time.RFC3339),
			"value_length": len(mod.Value),
		}

		// Try to decode value as JSON, fallback to string
		var decoded interface{}
		if json.Unmarshal(mod.Value, &decoded) == nil {
			record["value"] = decoded
		} else {
			record["value"] = string(mod.Value)
		}

		records = append(records, record)
	}

	out, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling history: %v", err)
	}

	return string(out), nil
}

/**************  MAIN **************************************************/
func main() {
	cc, err := contractapi.NewChaincode(&PIRChainCode{})
	if err != nil {
		panic(fmt.Sprintf("create cc: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("start cc: %v", err))
	}
}
