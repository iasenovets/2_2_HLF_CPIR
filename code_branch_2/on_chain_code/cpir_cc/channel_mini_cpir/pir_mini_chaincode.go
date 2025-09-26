// pir_mini_chaincode.go
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
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

/**************  DATA MODEL ********************************************/
type CTIRecordMini struct {
	MD5           string `json:"md5"`
	MalwareFamily string `json:"malware_family"`
	ThreatLevel   string `json:"threat_level"`
	Padding       string `json:"padding,omitempty"`
}

/**************  CHAINCODE STRUCT **************************************/
type PIRMiniChaincode struct {
	contractapi.Contract

	// Cryptographic context
	Params bgv.Parameters  // in-memory BGV params
	m_DB   *rlwe.Plaintext // in-memory plaintext poly

	// Metadata (mirror world state keys)
	NRecords    int // world state: "n"
	SlotsPerRec int // world state: "record_s"

	// Optional cache of JSON records (not required for PIR path)
	Records [][]byte // world state: "record%03d" keys
}

type AuditRecord struct {
	TxID      string `json:"tx_id"`
	Channel   string `json:"channel"`
	ClientMSP string `json:"client_msp"`
	ClientID  string `json:"client_id"`

	// EncQuery info (we persist the full B64 under a separate key)
	EncQueryLenB64 int    `json:"enc_query_len_b64"`
	EncQueryHead   string `json:"enc_query_b64_head"` // first 48 chars for quick debug

	// m_DB provenance (keep the hash—compact and verifiable)
	MDBSHA256   string `json:"m_DB_sha256"`
	SlotsPerRec int    `json:"slots_per_rec,omitempty"`
	DBSize      int    `json:"db_size,omitempty"`

	// Response size (B64)
	ResultLenB64 int `json:"result_len_b64"`
}

type PublicReadAudit struct {
	TxID      string `json:"tx_id"`
	Channel   string `json:"channel"`
	ClientMSP string `json:"client_msp"`
	ClientID  string `json:"client_id"`
	Key       string `json:"key"`
	ValueLen  int    `json:"value_len"`
	ValueHead string `json:"value_head"` // first bytes for quick diff in Explorer
}

/**************  INIT LEDGER *******************************************/
func (cc *PIRMiniChaincode) InitLedger(ctx contractapi.TransactionContextInterface, numRecordsStr, maxJsonLengthStr string) error {
	numRecords, err := strconv.Atoi(numRecordsStr)
	if err != nil || numRecords <= 0 {
		return fmt.Errorf("invalid number of records")
	}
	maxJsonLength, err := strconv.Atoi(maxJsonLengthStr)
	if err != nil || maxJsonLength <= 0 {
		return fmt.Errorf("invalid JSON length")
	}

	// 1) BGV params (as before)
	paramsLit := bgv.ParametersLiteral{LogN: 13, LogQ: []int{54}, LogP: []int{54}, PlaintextModulus: 65537}
	p, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		return fmt.Errorf("failed to set params: %v", err)
	}
	cc.Params = p

	// 2) Records
	records, err := generateMiniRecords(numRecords, maxJsonLength)
	if err != nil {
		return err
	}
	cc.Records = make([][]byte, len(records))

	// 3) Store JSON records
	for i, rec := range records {
		js, _ := json.Marshal(rec)
		cc.Records[i] = js
		if err := ctx.GetStub().PutState(fmt.Sprintf("record%03d", i), js); err != nil {
			return err
		}
	}

	// 4) Compute record_s
	maxLen := 0
	for _, js := range cc.Records {
		if len(js) > maxLen {
			maxLen = len(js)
		}
	}
	cc.SlotsPerRec = ((maxLen + 7) / 8) * 8
	if cc.SlotsPerRec == 0 {
		cc.SlotsPerRec = 8
	}

	// 5) Pack → m_DB
	packed := make([]uint64, p.MaxSlots())
	for i, js := range cc.Records {
		start := i * cc.SlotsPerRec
		for j := 0; j < len(js) && j < cc.SlotsPerRec; j++ {
			packed[start+j] = uint64(js[j])
		}
	}
	enc := bgv.NewEncoder(p)
	pt := bgv.NewPlaintext(p, p.MaxLevel())
	if err := enc.Encode(packed, pt); err != nil {
		return fmt.Errorf("failed to encode DB: %v", err)
	}
	cc.m_DB = pt

	// 6) Persist m_DB + metadata
	ptBytes, _ := pt.MarshalBinary()
	if err := ctx.GetStub().PutState("m_DB", ptBytes); err != nil {
		return fmt.Errorf("failed to save m_DB: %v", err)
	}
	if err := ctx.GetStub().PutState("n", []byte(fmt.Sprintf("%d", numRecords))); err != nil {
		return fmt.Errorf("failed to save n: %v", err)
	}
	if err := ctx.GetStub().PutState("record_s", []byte(fmt.Sprintf("%d", cc.SlotsPerRec))); err != nil {
		return fmt.Errorf("failed to save record_s: %v", err)
	}

	// 7) Persist minimal BGV params (for GetMetadata / client validation)
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
		T:     uint64(p.LogT()),
	}
	pm, _ := json.Marshal(paramsMeta)
	if err := ctx.GetStub().PutState("bgv_params", pm); err != nil {
		return fmt.Errorf("failed to save bgv_params: %v", err)
	}

	// 8) Mirror to struct scalar fields
	cc.NRecords = numRecords

	return nil
}

/**************  PIR QUERY *********************************************/
func (cc *PIRMiniChaincode) PIRQuery(ctx contractapi.TransactionContextInterface, encQueryB64 string) (string, error) {
	// Reload m_DB if not in memory
	if cc.m_DB == nil {
		raw, err := ctx.GetStub().GetState("m_DB")
		if err != nil {
			return "", err
		}
		pt := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel())
		if err := pt.UnmarshalBinary(raw); err != nil {
			return "", err
		}
		cc.m_DB = pt
		dbg("[CC] m_DB reloaded in memory")
	}

	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", err
	}
	ctQuery := rlwe.NewCiphertext(cc.Params, 1)
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", err
	}
	dbg("[CC] PIRQuery: received ciphertext (bytes=%d)", len(encBytes))

	eval := bgv.NewEvaluator(cc.Params, nil)
	ctRes, err := eval.MulNew(ctQuery, cc.m_DB)
	if err != nil {
		return "", err
	}

	outBytes, _ := ctRes.MarshalBinary()
	dbg("[CC] PIRQuery: returning result (bytes=%d)", len(outBytes))
	return base64.StdEncoding.EncodeToString(outBytes), nil
}

func (cc *PIRMiniChaincode) PIRQueryWithAudit(ctx contractapi.TransactionContextInterface, encQueryB64 string) (string, error) {
	// 1) Ensure m_DB is loaded
	if cc.m_DB == nil {
		raw, err := ctx.GetStub().GetState("m_DB")
		if err != nil {
			return "", err
		}
		pt := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel())
		if err := pt.UnmarshalBinary(raw); err != nil {
			return "", err
		}
		cc.m_DB = pt
		dbg("[CC] m_DB reloaded in memory")
	}

	// --- Optional size guard (tune to your needs) ---
	const maxAuditPayloadB64 = 512 * 1024 // 512 KB cap for EncQueryB64 on-ledger
	if len(encQueryB64) > maxAuditPayloadB64 {
		return "", fmt.Errorf("encQueryB64 too large (%d > %d bytes), refusing to audit-store payload",
			len(encQueryB64), maxAuditPayloadB64)
	}

	// 2) Decode client ciphertext (argument the peer sees)
	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", err
	}
	ctQuery := rlwe.NewCiphertext(cc.Params, 1)
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", err
	}
	dbg("[CC] PIRQueryWithAudit: received ciphertext (bytes=%d)", len(encBytes))

	// 3) PIR evaluation (ct × pt)
	eval := bgv.NewEvaluator(cc.Params, nil)
	ctRes, err := eval.MulNew(ctQuery, cc.m_DB)
	if err != nil {
		return "", err
	}
	outBytes, _ := ctRes.MarshalBinary()
	outB64 := base64.StdEncoding.EncodeToString(outBytes)
	dbg("[CC] PIRQueryWithAudit: returning result (bytes=%d)", len(outBytes))

	// 4) Build audit record with full payload stored separately
	//    - m_DB hash (compact provenance)
	m_DBBytes, _ := cc.m_DB.MarshalBinary()
	ph := sha256.Sum256(m_DBBytes)

	//    - client identity
	cidLib, _ := cid.New(ctx.GetStub())
	mspID, _ := cidLib.GetMSPID()
	clientID, _ := cidLib.GetID()

	//    - tx/channel
	txID := ctx.GetStub().GetTxID()
	channel := "" // Fabric stub doesn't expose channel; pass it as an arg if you need it.

	// head preview (48 chars like your client debug)
	head := encQueryB64
	if len(head) > 48 {
		head = head[:48] + "..."
	}

	audit := AuditRecord{
		TxID:           txID,
		Channel:        channel,
		ClientMSP:      mspID,
		ClientID:       clientID,
		EncQueryLenB64: len(encQueryB64),
		EncQueryHead:   head,
		MDBSHA256:      hex.EncodeToString(ph[:]),
		ResultLenB64:   len(outB64),
	}
	auditJSON, _ := json.Marshal(audit)

	// 5) Write compact audit record
	auditKey := "audit:" + txID
	if err := ctx.GetStub().PutState(auditKey, auditJSON); err != nil {
		return "", err
	}

	// 6) Write the full EncQueryB64 under a companion key
	payloadKey := "audit:payload:" + txID
	if err := ctx.GetStub().PutState(payloadKey, []byte(encQueryB64)); err != nil {
		return "", err
	}

	return outB64, nil
}

/**************  PUBLIC QUERIES ***************************************/
func (cc *PIRMiniChaincode) PublicQueryCTI(ctx contractapi.TransactionContextInterface, key string) (*CTIRecordMini, error) {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("record not found")
	}
	var r CTIRecordMini
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (cc *PIRMiniChaincode) PublicQueryCTIWithAudit(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	// Read the value exactly as in the evaluate path
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", err
	}
	if b == nil {
		return "", fmt.Errorf("record not found")
	}

	// For easy container-log comparison
	head := string(b)
	if len(head) > 64 {
		head = head[:64] + "..."
	}
	dbg("[CC] PublicQueryCTIWithAudit (submit) key=%s len=%d head=%q", key, len(b), head)

	// Identity + tx info (stable across endorsers)
	cidLib, _ := cid.New(ctx.GetStub())
	mspID, _ := cidLib.GetMSPID()
	clientID, _ := cidLib.GetID()
	txID := ctx.GetStub().GetTxID()
	channel := "" // not exposed by stub; pass it as arg if needed

	// Compose compact audit JSON
	a := PublicReadAudit{
		TxID:      txID,
		Channel:   channel,
		ClientMSP: mspID,
		ClientID:  clientID,
		Key:       key,
		ValueLen:  len(b),
		ValueHead: head,
	}
	aJSON, _ := json.Marshal(a)

	// Write compact audit entry
	auditKey := "audit:public:" + txID
	if err := ctx.GetStub().PutState(auditKey, aJSON); err != nil {
		return "", err
	}

	// Optionally: persist full payloads for deep diffs (toggle if you want)
	// _ = ctx.GetStub().PutState("audit:public:key:"+txID, []byte(key))
	// _ = ctx.GetStub().PutState("audit:public:value:"+txID, b)

	// Return the record as raw JSON string to the client (handy for paper/demo)
	return string(b), nil
}

// GetMetadata returns {"numRecords": n, "slotsPerRec": s} as JSON.
/**************  GET METADATA *******************************************/
func (cc *PIRMiniChaincode) GetMetadata(ctx contractapi.TransactionContextInterface) (string, error) {
	// --- 1) Load n ---
	nBytes, err := ctx.GetStub().GetState("n")
	if err != nil || nBytes == nil {
		return "", fmt.Errorf("missing n in world state")
	}
	n, _ := strconv.Atoi(string(nBytes))

	// --- 2) Load record_s ---
	sBytes, err := ctx.GetStub().GetState("record_s")
	if err != nil || sBytes == nil {
		return "", fmt.Errorf("missing record_s in world state")
	}
	recordS, _ := strconv.Atoi(string(sBytes))

	// --- 3) Load BGV params ---
	paramsBytes, err := ctx.GetStub().GetState("bgv_params")
	if err != nil || paramsBytes == nil {
		return "", fmt.Errorf("missing bgv_params in world state")
	}

	// Unmarshal stored metadata
	var paramsMeta struct {
		LogN  int    `json:"logN"`
		N     int    `json:"N"`
		LogQi []int  `json:"logQi"`
		LogPi []int  `json:"logPi"`
		T     uint64 `json:"t"`
	}
	if err := json.Unmarshal(paramsBytes, &paramsMeta); err != nil {
		return "", fmt.Errorf("failed to parse bgv_params: %v", err)
	}

	// --- 4) Merge into one metadata blob ---
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
		return "", fmt.Errorf("failed to marshal metadata: %v", err)
	}
	return string(out), nil
}

/**************  RECORD GENERATOR **************************************/
func generateMiniRecords(n int, maxJsonLength int) ([]CTIRecordMini, error) {
	families := []string{"Emotet", "Ryuk", "AgentTesla"}
	levels := []string{"Low", "Medium", "High", "Critical"}
	records := make([]CTIRecordMini, n)

	for i := 0; i < n; i++ {
		rec := CTIRecordMini{
			MD5:           fakeHash("md5", i, 32),
			MalwareFamily: families[i%len(families)],
			ThreatLevel:   levels[i%len(levels)],
		}
		js, _ := json.Marshal(rec)
		remaining := maxJsonLength - len(js)
		if remaining > 0 {
			rec.Padding = fakeHash("pad", i, remaining)
		}
		records[i] = rec
	}
	return records, nil
}

func fakeHash(prefix string, i int, length int) string {
	data := []byte(fmt.Sprintf("%s%d", prefix, i))
	out := ""
	for len(out) < length {
		out += base64.StdEncoding.EncodeToString(data)
		data = []byte(out)
	}
	return out[:length]
}

/**************  MAIN **************************************************/
func main() {
	cc, err := contractapi.NewChaincode(&PIRMiniChaincode{})
	if err != nil {
		panic(fmt.Sprintf("create cc: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("start cc: %v", err))
	}
}
