package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

/********* модели *************************************************/
type CTIRecord struct {
	MD5           string `json:"md5"`
	SHA256        string `json:"sha256"`
	MalwareClass  string `json:"malware_class"`
	MalwareFamily string `json:"malware_family"`
	AVDetects     int    `json:"av_detects"`
	ThreatLevel   string `json:"threat_level"`
}

type request struct {
	Method string   `json:"method"`
	Args   []string `json:"args"`
}
type response struct {
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

/********* глобальное «состояние блокчейна» ***********************/
var (
	mtx     sync.RWMutex
	params  bgv.Parameters
	ptdb    *rlwe.Plaintext
	records []CTIRecord
)

/********* init HE params *****************************************/
func initParams() error {
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
	params = p

	return nil
}

/********* хэндлер invoke ******************************************/
func invoke(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, err)
		return
	}

	switch req.Method {
	//----------------------------------------------
	case "InitLedger":
		initLedger()
		writeOK(w, "done")

	case "PublicQueryCTI":
		if len(req.Args) != 1 {
			writeErr(w, fmt.Errorf("arg 0 = key"))
			return
		}
		key := req.Args[0]
		idx := atoi(key[len(key)-3:]) // record000 → 0
		if idx >= len(records) {
			writeErr(w, fmt.Errorf("not found"))
			return
		}
		js, _ := json.Marshal(records[idx])
		writeOK(w, string(js))

	case "PublicQueryALL":
		writeOK(w, fmt.Sprintf("%d", len(records)))

	case "PIRQuery":
		if len(req.Args) != 1 {
			writeErr(w, fmt.Errorf("need encQueryB64"))
			return
		}
		outB64, err := pirQuery(req.Args[0])
		if err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w, outB64)

	default:
		writeErr(w, fmt.Errorf("unknown method"))
	}
}

/********* бизнес-логика ******************************************/
func initLedger() {
	mtx.Lock()
	defer mtx.Unlock()

	records = []CTIRecord{
		{"d41d8cd98f00b204e9800998ecf8427e", "…", "Trojan", "Emotet", 42, "High"},
		{"0cc175b9c0f1b6a831c399e269772661", "…", "Worm", "WannaCry", 37, "Critical"},
		{"900150983cd24fb0d6963f7d28e17f72", "…", "Ransomware", "Ryuk", 29, "High"},
	}

	enc := bgv.NewEncoder(params)
	packed := make([]uint64, params.MaxSlots())
	for i, r := range records {
		packed[i] = hashToUint64(r.MD5)
	}
	fmt.Printf("[DBG] packed[0..2] = %v\n", packed[:10]) // [2211 2104 2107]

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	enc.Encode(packed, pt)
	ptdb = pt
	fmt.Println("[DBG] PTDB ready (encoded)")
}

func pirQuery(encQueryB64 string) (string, error) {
	mtx.RLock()
	defer mtx.RUnlock()

	encBytes, _ := base64.StdEncoding.DecodeString(encQueryB64)
	ctQuery := rlwe.NewCiphertext(params, 1)
	if err := ctQuery.UnmarshalBinary(encBytes); err != nil {
		return "", err
	}

	eval := bgv.NewEvaluator(params, nil)
	ctRes, _ := eval.MulNew(ctQuery, ptdb)

	outBytes, _ := ctRes.MarshalBinary()
	return base64.StdEncoding.EncodeToString(outBytes), nil
}

/********* утилиты *************************************************/
func writeOK(w http.ResponseWriter, resp string) {
	json.NewEncoder(w).Encode(response{Response: resp})
}
func writeErr(w http.ResponseWriter, err error) {
	json.NewEncoder(w).Encode(response{Error: err.Error()})
}
func atoi(s string) int { var n int; fmt.Sscan(s, &n); return n }
func hashToUint64(s string) uint64 {
	var sum uint64
	for _, c := range s {
		sum += uint64(c)
	}
	res := sum % 65537
	fmt.Printf("[DBG] hashToUint64(%s) = %d\n", s[:6]+"…", res)
	return res
}

/********* main ***************************************************/
func main() {
	initParams()
	http.HandleFunc("/invoke", invoke)
	fmt.Println("REST chaincode listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
