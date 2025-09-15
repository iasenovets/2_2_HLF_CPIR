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
	Params      bgv.Parameters
	SlotsPerRec int
	PTDB        *rlwe.Plaintext
}

type AuditRecord struct {
	TxID      string `json:"tx_id"`
	Channel   string `json:"channel"`
	ClientMSP string `json:"client_msp"`
	ClientID  string `json:"client_id"`

	// EncQuery info (we persist the full B64 under a separate key)
	EncQueryLenB64 int    `json:"enc_query_len_b64"`
	EncQueryHead   string `json:"enc_query_b64_head"` // first 48 chars for quick debug

	// PTDB provenance (keep the hash—compact and verifiable)
	PTDBSHA256  string `json:"ptdb_sha256"`
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
func (cc *PIRMiniChaincode) InitLedger(ctx contractapi.TransactionContextInterface, numRecordsStr string, maxJsonLengthStr string) error {
	numRecords, err := strconv.Atoi(numRecordsStr)
	if err != nil || numRecords <= 0 {
		return fmt.Errorf("invalid number of records")
	}
	maxJsonLength, err := strconv.Atoi(maxJsonLengthStr)
	if err != nil || maxJsonLength <= 0 {
		return fmt.Errorf("invalid JSON length")
	}

	// 1. Setup BGV Params for channel_mini
	paramsLit := bgv.ParametersLiteral{
		LogN:             13,        // channel_mini uses logN=13
		LogQ:             []int{54}, // ciphertext modulus
		LogP:             []int{54}, // special prime
		PlaintextModulus: 65537,
	}
	p, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		return fmt.Errorf("failed to set params: %v", err)
	}
	cc.Params = p
	dbg("[CC] Params: LogN=%d, MaxSlots=%d", p.LogN(), p.MaxSlots())

	// 2. Generate synthetic CTI records
	records, err := generateMiniRecords(numRecords, maxJsonLength)
	if err != nil {
		return err
	}

	// 3. Store each record JSON in ledger
	for i, rec := range records {
		js, _ := json.Marshal(rec)
		key := fmt.Sprintf("record%03d", i)
		if err := ctx.GetStub().PutState(key, js); err != nil {
			return err
		}
	}
	dbg("[CC] Stored %d CTI records in world state", len(records))

	// 4. Compute SlotsPerRecord
	maxLen := 0
	for _, rec := range records {
		js, _ := json.Marshal(rec)
		if len(js) > maxLen {
			maxLen = len(js)
		}
	}
	cc.SlotsPerRec = ((maxLen + 7) / 8) * 8
	dbg("[CC] Max JSON length=%d -> SlotsPerRec=%d", maxLen, cc.SlotsPerRec)

	// 5. Pack all records into PTDB
	packed := make([]uint64, p.MaxSlots())
	for i, rec := range records {
		js, _ := json.Marshal(rec)
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
	cc.PTDB = pt

	// 6. Save PTDB in ledger
	ptBytes, _ := pt.MarshalBinary()
	if err := ctx.GetStub().PutState("PTDB", ptBytes); err != nil {
		return fmt.Errorf("failed to save PTDB: %v", err)
	}
	dbg("[CC] PTDB encoded and stored (bytes=%d)", len(ptBytes))

	return nil
}

/**************  PIR QUERY *********************************************/
func (cc *PIRMiniChaincode) PIRQuery(ctx contractapi.TransactionContextInterface, encQueryB64 string) (string, error) {
	// Reload PTDB if not in memory
	if cc.PTDB == nil {
		raw, err := ctx.GetStub().GetState("PTDB")
		if err != nil {
			return "", err
		}
		pt := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel())
		if err := pt.UnmarshalBinary(raw); err != nil {
			return "", err
		}
		cc.PTDB = pt
		dbg("[CC] PTDB reloaded in memory")
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
	ctRes, err := eval.MulNew(ctQuery, cc.PTDB)
	if err != nil {
		return "", err
	}

	outBytes, _ := ctRes.MarshalBinary()
	dbg("[CC] PIRQuery: returning result (bytes=%d)", len(outBytes))
	return base64.StdEncoding.EncodeToString(outBytes), nil
}

func (cc *PIRMiniChaincode) PIRQueryWithAudit(ctx contractapi.TransactionContextInterface, encQueryB64 string) (string, error) {
	// 1) Ensure PTDB is loaded
	if cc.PTDB == nil {
		raw, err := ctx.GetStub().GetState("PTDB")
		if err != nil {
			return "", err
		}
		pt := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel())
		if err := pt.UnmarshalBinary(raw); err != nil {
			return "", err
		}
		cc.PTDB = pt
		dbg("[CC] PTDB reloaded in memory")
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
	ctRes, err := eval.MulNew(ctQuery, cc.PTDB)
	if err != nil {
		return "", err
	}
	outBytes, _ := ctRes.MarshalBinary()
	outB64 := base64.StdEncoding.EncodeToString(outBytes)
	dbg("[CC] PIRQueryWithAudit: returning result (bytes=%d)", len(outBytes))

	// 4) Build audit record with full payload stored separately
	//    - PTDB hash (compact provenance)
	ptdbBytes, _ := cc.PTDB.MarshalBinary()
	ph := sha256.Sum256(ptdbBytes)

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
		PTDBSHA256:     hex.EncodeToString(ph[:]),
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

func (cc *PIRMiniChaincode) PublicQueryALL(ctx contractapi.TransactionContextInterface) (int, error) {
	it, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return 0, err
	}
	defer it.Close()
	count := 0
	for it.HasNext() {
		it.Next()
		count++
	}
	return count - 1, nil // exclude PTDB entry
}

/**************  GET SLOTS PER RECORD *********************************/
func (cc *PIRMiniChaincode) GetSlotsPerRecord(ctx contractapi.TransactionContextInterface) (int, error) {
	return cc.SlotsPerRec, nil
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
