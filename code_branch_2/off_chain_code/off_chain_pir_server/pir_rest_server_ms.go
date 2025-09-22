package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

/********* МОДЕЛИ *************************************************/

// CTIRecordMini для channel_mini: компактные записи.
type CTIRecordMini struct {
	MD5           string `json:"md5"`
	MalwareFamily string `json:"malware_family"`
	ThreatLevel   string `json:"threat_level"`
	Padding       string `json:"padding,omitempty"` // Добавлено для регулировки размера
}

// CTIRecordMid для channel_mid: баланс между детализацией и размером.
type CTIRecordMid struct {
	MD5           string `json:"md5"`
	SHA256Short   string `json:"sha256_short"`
	MalwareClass  string `json:"malware_class"`
	MalwareFamily string `json:"malware_family"`
	AVDetects     int    `json:"av_detects"`
	ThreatLevel   string `json:"threat_level"`
	Padding       string `json:"padding,omitempty"` // Добавлено для регулировки размера
}

// CTIRecordRich для channel_rich: полные записи со всеми хешами.
type CTIRecordRich struct {
	MD5           string `json:"md5"`
	SHA256        string `json:"sha256"`
	MalwareClass  string `json:"malware_class"`
	MalwareFamily string `json:"malware_family"`
	AVDetects     int    `json:"av_detects"`
	ThreatLevel   string `json:"threat_level"`
	Padding       string `json:"padding,omitempty"` // Добавлено для регулировки размера
}

type request struct {
	Method string   `json:"method"`
	Args   []string `json:"args"`
}
type response struct {
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

/********* ГЛОБАЛЬНОЕ «СОСТОЯНИЕ БЛОКЧЕЙНА» ***********************/
var (
	mtx         sync.RWMutex
	params      bgv.Parameters
	ptdb        *rlwe.Plaintext
	records     [][]byte
	slotsPerRec int
)

/********* ИНИЦИАЛИЗАЦИЯ HE PARAMS *****************************************/
func createParams(logN int) (bgv.Parameters, error) {
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

/********* ХЭНДЛЕР INVOKE ******************************************/
func invoke(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, err)
		return
	}

	switch req.Method {
	case "InitLedger":
		if len(req.Args) != 3 {
			writeErr(w, fmt.Errorf("InitLedger requires exactly 3 arguments: numRecords, maxJsonLength, channel"))
			return
		}

		n, err1 := strconv.Atoi(req.Args[0])
		maxJsonLength, err2 := strconv.Atoi(req.Args[1])
		channel := req.Args[2]

		if err1 != nil || err2 != nil || n <= 0 || maxJsonLength <= 0 {
			writeErr(w, fmt.Errorf("numRecords and maxJsonLength must be positive integers"))
			return
		}
		if channel == "" {
			writeErr(w, fmt.Errorf("channel cannot be empty"))
			return
		}

		// Определяем logN на основе канала
		logN := map[string]int{
			"channel_mini": 13,
			"channel_mid":  14,
			"channel_rich": 15,
		}[channel]
		if logN == 0 {
			writeErr(w, fmt.Errorf("invalid channel: %s", channel))
			return
		}

		err := initLedger(n, maxJsonLength, channel, logN)
		if err != nil {
			log.Printf("[ERROR] Failed to init ledger from invoke: %v", err)
			writeErr(w, err)
			return
		}
		writeOK(w, fmt.Sprintf("ledger initialised with %d records for '%s' (LogN=%d) using slotsPerRec=%d", n, channel, logN, slotsPerRec))

	case "GetSlotsPerRecord":
		writeOK(w, fmt.Sprintf("%d", slotsPerRec))

	case "PublicQueryCTI":
		if len(req.Args) != 1 {
			writeErr(w, fmt.Errorf("arg 0 = key (e.g., record000)"))
			return
		}
		key := req.Args[0]
		idx, err := strconv.Atoi(key[len(key)-3:])
		if err != nil || idx < 0 {
			writeErr(w, fmt.Errorf("invalid record index from key %s", key))
			return
		}

		mtx.RLock()
		defer mtx.RUnlock()
		if idx >= len(records) {
			writeErr(w, fmt.Errorf("not found"))
			return
		}
		writeOK(w, string(records[idx]))

	case "PublicQueryALL":
		mtx.RLock()
		defer mtx.RUnlock()
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

/********* БИЗНЕС-ЛОГИКА ******************************************/
func initLedger(n int, maxJsonLength int, channel string, logN int) error {
	mtx.Lock()
	defer mtx.Unlock()

	// 1. Create BGV parameters
	p, err := createParams(logN)
	if err != nil {
		return err
	}
	params = p
	log.Printf("[INFO] Initializing ledger with LogN=%d (Ring size = %d slots)", logN, params.MaxSlots())

	// 2. Generate synthetic records
	genRecords, err := generateRecords(n, channel, maxJsonLength)
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
	calcSlotsPerRec()
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
	debugPrintRecords(ptdb)
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

/********* ГЕНЕРАЦИЯ ЗАПИСЕЙ *************************************************/
var malwareClasses = []string{"Trojan", "Worm", "Ransomware", "Backdoor", "Spyware"}
var malwareFamilies = []string{"Emotet", "WannaCry", "Ryuk", "AgentTesla", "Pegasus"}
var threatLevels = []string{"Low", "Medium", "High", "Critical"}

func fakeHash(prefix string, i int, length int) string {
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

func generateRecords(n int, channel string, maxJsonLength int) ([][]byte, error) {
	// 1. Checking allowed values of maxJsonLength
	validLengths := []int{64, 128, 224, 256, 384, 512}
	valid := false
	for _, l := range validLengths {
		if maxJsonLength == l {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("maxJsonLength %d is not in allowed set: %v", maxJsonLength, validLengths)
	}

	// 2. Checking maxed amount of records
	logN := map[string]int{
		"channel_mini": 13,
		"channel_mid":  14,
		"channel_rich": 15,
	}[channel]
	if logN == 0 {
		return nil, fmt.Errorf("unknown channel: %s", channel)
	}
	ringSize := 1 << logN
	maxDBSize := ringSize / ((maxJsonLength + 7) / 8)

	if n > maxDBSize {
		log.Printf("[WARN] Requested %d records exceed MaxDBSize %d for channel %s and maxJsonLength %d. Adjusting to %d.", n, maxDBSize, channel, maxJsonLength, maxDBSize)
		n = maxDBSize
	}

	records := make([][]byte, n)
	log.Printf("[INFO] Generating %d records for '%s' with target max JSON length: %d bytes", n, channel, maxJsonLength)

	// 3. Generating records based on the passed parameters
	for i := 0; i < n; i++ {
		var recBytes []byte
		var err error
		switch channel {
		case "channel_mini":
			recBytes, err = generateMiniRecord(i, maxJsonLength, n)
		case "channel_mid":
			recBytes, err = generateMidRecord(i, maxJsonLength, n)
		case "channel_rich":
			recBytes, err = generateRichRecord(i, maxJsonLength, n)
		default:
			return nil, fmt.Errorf("unknown channel: %s", channel)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to generate record %d: %w", i, err)
		}
		if len(recBytes) > maxJsonLength {
			log.Printf("[WARN] Record %d for channel '%s' exceeded max length. Got: %d, Max: %d", i, channel, len(recBytes), maxJsonLength)
		} else if len(recBytes) < maxJsonLength-8 {
			log.Printf("[WARN] Record %d for channel '%s' is too small. Got: %d, Max: %d", i, channel, len(recBytes), maxJsonLength)
		}
		records[i] = recBytes
	}

	return records, nil
}

func generateRichRecord(i int, maxJsonLength int, total int) ([]byte, error) {
	baseRec := CTIRecordRich{
		MalwareClass:  malwareClasses[i%len(malwareClasses)],
		MalwareFamily: malwareFamilies[i%len(malwareFamilies)],
		AVDetects:     (i % 50) + 1,
		ThreatLevel:   threatLevels[i%len(threatLevels)],
	}
	baseBytes, _ := json.Marshal(baseRec)
	baseSize := len(baseBytes)
	remaining := maxJsonLength - baseSize - 32 - 64 - 15

	if shouldPrintDebug(i, total) {
		fmt.Printf("[DBG] RichRecord[%03d]: baseSize=%d, remaining=%d (maxJsonLen=%d)\n",
			i, baseSize, remaining, maxJsonLength)
	}

	if remaining < 0 {
		return nil, fmt.Errorf("maxJsonLength %d is too small for a rich record (base size %d + hashes)", maxJsonLength, baseSize)
	}

	md5Len := 32
	shaLen := 64

	finalRec := CTIRecordRich{
		MD5:           fakeHash("md5", i, md5Len),
		SHA256:        fakeHash("sha", i, shaLen),
		MalwareClass:  baseRec.MalwareClass,
		MalwareFamily: baseRec.MalwareFamily,
		AVDetects:     baseRec.AVDetects,
		ThreatLevel:   baseRec.ThreatLevel,
		Padding:       fakeHash("pad", i, remaining),
	}
	recBytes, err := json.Marshal(finalRec)
	if err != nil {
		return nil, err
	}
	return recBytes, nil
}

func generateMidRecord(i int, maxJsonLength int, total int) ([]byte, error) {
	baseRec := CTIRecordMid{
		MalwareClass:  malwareClasses[i%len(malwareClasses)],
		MalwareFamily: malwareFamilies[i%len(malwareFamilies)],
		AVDetects:     (i % 50) + 1,
		ThreatLevel:   threatLevels[i%len(threatLevels)],
	}
	baseBytes, _ := json.Marshal(baseRec)
	baseSize := len(baseBytes)
	remaining := maxJsonLength - baseSize - 32 - 16 - 15

	if shouldPrintDebug(i, total) {
		fmt.Printf("[DBG] MidRecord[%03d]: baseSize=%d, remaining=%d (maxJsonLen=%d)\n",
			i, baseSize, remaining, maxJsonLength)
	}

	if remaining < 0 {
		return nil, fmt.Errorf("maxJsonLength %d is too small for a mid record (base size %d + hashes)", maxJsonLength, baseSize)
	}

	md5Len := 32
	shaShortLen := 16

	finalRec := CTIRecordMid{
		MD5:           fakeHash("md5", i, md5Len),
		SHA256Short:   fakeHash("sha_short", i, shaShortLen),
		MalwareClass:  baseRec.MalwareClass,
		MalwareFamily: baseRec.MalwareFamily,
		AVDetects:     baseRec.AVDetects,
		ThreatLevel:   baseRec.ThreatLevel,
		Padding:       fakeHash("pad", i, remaining),
	}
	recBytes, err := json.Marshal(finalRec)
	if err != nil {
		return nil, err
	}
	return recBytes, nil
}

func generateMiniRecord(i int, maxJsonLength int, total int) ([]byte, error) {
	baseRec := CTIRecordMini{
		MalwareFamily: malwareFamilies[i%len(malwareFamilies)],
		ThreatLevel:   threatLevels[i%len(threatLevels)],
	}
	baseBytes, _ := json.Marshal(baseRec)
	baseSize := len(baseBytes)
	remaining := maxJsonLength - baseSize - 32 - 15

	if shouldPrintDebug(i, total) {
		fmt.Printf("[DBG] MiniRecord[%03d]: baseSize=%d, remaining=%d (maxJsonLen=%d)\n",
			i, baseSize, remaining, maxJsonLength)
	}

	if remaining < 0 {
		return nil, fmt.Errorf("maxJsonLength %d is too small for a mini record (base size %d + md5)", maxJsonLength, baseSize)
	}

	md5Len := 32

	finalRec := CTIRecordMini{
		MD5:           fakeHash("md5", i, md5Len),
		MalwareFamily: baseRec.MalwareFamily,
		ThreatLevel:   baseRec.ThreatLevel,
		Padding:       fakeHash("pad", i, remaining),
	}
	recBytes, err := json.Marshal(finalRec)
	if err != nil {
		return nil, err
	}
	return recBytes, nil
}

/********* UTILS *************************************************/
func shouldPrintDebug(i, total int) bool {
	// Print first 3 and last 3 records
	return i < 3 || i >= total-3
}

func calcSlotsPerRec() {
	max := 0
	for _, recBytes := range records {
		if len(recBytes) > max {
			max = len(recBytes)
		}
	}
	slotsPerRec = ((max + 7) / 8) * 8
	if slotsPerRec == 0 {
		slotsPerRec = 8
	}

	log.Printf("[DEBUG] Max actual JSON len = %d bytes", max)
	log.Printf("[DEBUG] slotsPerRec calculated = %d  ( = %d × 8-byte blocks)",
		slotsPerRec, slotsPerRec/8)
}

func debugPrintRecords(pt *rlwe.Plaintext) {
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

func writeOK(w http.ResponseWriter, resp string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response{Response: resp})
}
func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response{Error: err.Error()})
}

/********* MAIN ***************************************************/
func main() {
	http.HandleFunc("/invoke", invoke)
	log.Println("REST chaincode listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
