// pir_chaincode.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

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

// --------------------------------------------------
//  1.  Data model
// --------------------------------------------------

type CTIRecord struct {
	MD5           string `json:"md5"`
	SHA256        string `json:"sha256"`
	MalwareClass  string `json:"malware_class"`
	MalwareFamily string `json:"malware_family"`
	AVDetects     int    `json:"av_detects"`
	ThreatLevel   string `json:"threat_level"`
}

// --------------------------------------------------
//  2.  Chaincode struct
// --------------------------------------------------

type PIRChaincode struct {
	contractapi.Contract
	Params bgv.Parameters  // public HE parameters (same as client)
	PTDB   *rlwe.Plaintext // plaintext packing the whole DB
}

// --------------------------------------------------
//  3.  Init -- set HE params & build plaintext DB
// --------------------------------------------------

func (cc *PIRChaincode) InitLedger(ctx contractapi.TransactionContextInterface) error {

	// ---- 3.1   set the SAME parameters literal as client -------------
	paramsLit := bgv.ParametersLiteral{
		LogN:             13,        // 8192 slots
		LogQ:             []int{54}, // one 54-bit ciphertext prime (auto-picked)
		LogP:             []int{54}, // one 54-bit special prime
		PlaintextModulus: 65537,     // T
	}
	p, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		return fmt.Errorf("bad HE parameters: %v", err)
	}
	cc.Params = p // keep in struct
	dbg("[CC] Params loaded: N=%d  MaxSlots=%d  |Q|=%d primes",
		1<<p.LogN(), p.MaxSlots(), len(p.Q()))

	// ---- 3.2  sample CTI records -----------------------------------
	records := []CTIRecord{
		{"d41d8cd98f00b204e9800998ecf8427e", "…", "Trojan", "Emotet", 42, "High"},
		{"0cc175b9c0f1b6a831c399e269772661", "…", "Worm", "WannaCry", 37, "Critical"},
		{"900150983cd24fb0d6963f7d28e17f72", "…", "Ransomware", "Ryuk", 29, "High"},
	}
	// you can later AddCTIRecord to append more (up to slots capacity)

	// ---- 3.3  write JSON copies into world-state --------------------
	for i, r := range records {
		key := fmt.Sprintf("record%03d", i)
		js, _ := json.Marshal(r)
		ctx.GetStub().PutState(key, js)
	}
	dbg("[CC] Stored %d JSON records (keys record000..)", len(records))

	// ---- 3.4  build one plaintext packing ALL records ---------------
	slots := p.MaxSlots() // 8192
	packed := make([]uint64, slots)

	for i, r := range records {
		// simple numeric encoding = ASCII-sum of MD5 (fits in 16 bits)
		packed[i] = hashToUint64(r.MD5)
	}

	enc := bgv.NewEncoder(p)
	pt := bgv.NewPlaintext(p, p.MaxLevel())
	if err := enc.Encode(packed, pt); err != nil {
		return err
	}
	cc.PTDB = pt

	// store ptDB bytes in ledger so all peers can reload on restart
	ptBytes, _ := pt.MarshalBinary()
	ctx.GetStub().PutState("PTDB", ptBytes)
	dbg("[CC] PTDB encoded   : coeffs[0..2]=%v  byteLen=%d", packed[:3], len(ptBytes))

	return nil
}

// --------------------------------------------------
//  4.  Add a new CTI record (and update plaintext DB)
// --------------------------------------------------

func (cc *PIRChaincode) AddCTIRecord(ctx contractapi.TransactionContextInterface,
	index int, recordJSON string) error {

	// 1) Store JSON copy in world-state
	key := fmt.Sprintf("record%03d", index)
	if err := ctx.GetStub().PutState(key, []byte(recordJSON)); err != nil {
		return err
	}
	dbg("[CC] AddCTIRecord   : key=%s", key)

	// 2) Parse JSON so we can encode its MD5
	var rec CTIRecord
	if err := json.Unmarshal([]byte(recordJSON), &rec); err != nil {
		return err
	}
	//newVal := hashToUint64(rec.MD5)

	// 3) ---- update slot in cc.PTDB ---------------------------------
	slots := cc.Params.MaxSlots()
	vec := make([]uint64, slots) // 3a. decode current PTDB
	enc := bgv.NewEncoder(cc.Params)
	if err := enc.Decode(cc.PTDB, vec); err != nil {
		return err
	}
	vec[index] = hashToUint64(rec.MD5) // 3b. overwrite slot 'index'

	ptNew := bgv.NewPlaintext(cc.Params, cc.Params.MaxLevel()) // 3c. re-encode into a *new* plaintext (same level)
	if err := enc.Encode(vec, ptNew); err != nil {
		return err
	}
	cc.PTDB = ptNew

	// 4) persist updated PTDB bytes so peers stay in sync
	ptBytes, _ := ptNew.MarshalBinary()
	ctx.GetStub().PutState("PTDB", ptBytes)
	dbg("[CC] PTDB slot %d updated -> %d", index, vec[index])
	return nil
}

// --------------------------------------------------
//  5.  Public plaintext query (debug / demo)
// --------------------------------------------------

func (cc *PIRChaincode) PublicQueryCTI(ctx contractapi.TransactionContextInterface, id string) (*CTIRecord, error) {
	b, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("record not found")
	}
	var r CTIRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	dbg("[CC] PublicQueryCTI : key=%s  MD5=%s", id, r.MD5[:6]+"…")
	return &r, nil
}

// PublicQueryALL returns the total number of CTI records
func (s *PIRChaincode) PublicQueryALL(ctx contractapi.TransactionContextInterface) (int, error) {
	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return 0, err
	}
	defer iterator.Close()

	count := 0
	for iterator.HasNext() {
		iterator.Next()
		count++
	}
	dbg("[CC] PublicQueryALL : total=%d entries incl. PTDB", count)
	return count, nil
}

// --------------------------------------------------
//  6.  PIR query: Enc(query) × PTDB  --------------
// --------------------------------------------------

func (cc *PIRChaincode) PIRQuery(ctx contractapi.TransactionContextInterface,
	encQueryB64 string) (string, error) {

	// 6.1 reload PTDB if not in memory (peer crash/restart)
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
		dbg("[CC] PTDB reloaded in memory (len=%d)", len(raw))
	}

	// 6.2 decode client ciphertext
	encBytes, err := base64.StdEncoding.DecodeString(encQueryB64)
	if err != nil {
		return "", err
	}
	ctQuery := rlwe.NewCiphertext(cc.Params, 1) // degree 1 (fresh)
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", err
	}

	dbg("[CC] PIRQuery recv  : B64len=%d, bytes=%d, level=%d", len(encQueryB64), len(encBytes), ctQuery.Level())

	// 6.3 homomorphic multiply
	eval := bgv.NewEvaluator(cc.Params, nil)
	ctRes, err := eval.MulNew(ctQuery, cc.PTDB) // cipher × plain (depth 1)

	// 6.4 return ciphertext (Base64) to client
	outBytes, _ := ctRes.MarshalBinary()
	dbg("[CC] PIRQuery       : result bytes=%d  returning B64 len=%d",
		len(outBytes), len(encQueryB64))

	return base64.StdEncoding.EncodeToString(outBytes), nil
}

// --------------------------------------------------
//  7.  tiny helper: cheap MD5→u64 “encoding” --------
// --------------------------------------------------

func hashToUint64(s string) uint64 {
	var sum uint64
	for _, c := range s {
		sum += uint64(c)
	}
	return sum % 65537 // keeps it < plaintext modulus
}

// --------------------------------------------------
//  8.  main() --------------------------------------
// --------------------------------------------------

func main() {
	chaincode, err := contractapi.NewChaincode(&PIRChaincode{})
	if err != nil {
		panic(fmt.Sprintf("create cc: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("start cc: %v", err))
	}
}
