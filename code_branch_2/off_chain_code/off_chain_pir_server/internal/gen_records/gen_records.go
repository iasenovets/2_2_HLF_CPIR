package gen_records

import (
	"encoding/json"
	"fmt"
	"log"

	"off-chain-pir-server/internal/utils"
)

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

/********* ГЕНЕРАЦИЯ ЗАПИСЕЙ *************************************************/
var malwareClasses = []string{"Trojan", "Worm", "Ransomware", "Backdoor", "Spyware"}
var malwareFamilies = []string{"Emotet", "WannaCry", "Ryuk", "AgentTesla", "Pegasus"}
var threatLevels = []string{"Low", "Medium", "High", "Critical"}

func GenerateRecords(n int, logN int, maxJsonLength int) ([][]byte, error) {
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
	ringSize := 1 << logN
	maxDBSize := ringSize / ((maxJsonLength + 7) / 8)

	if n > maxDBSize {
		log.Printf("[WARN] Requested %d records exceed MaxDBSize %d for logN %d and maxJsonLength %d. Adjusting to %d.", n, maxDBSize, logN, maxJsonLength, maxDBSize)
		n = maxDBSize
	}

	records := make([][]byte, n)
	log.Printf("[INFO] Generating %d records for logN=%d with target max JSON length: %d bytes", n, logN, maxJsonLength)

	// 3. Determine record type based on logN
	var generateFunc func(int, int, int) ([]byte, error)
	switch logN {
	case 13:
		generateFunc = generateMiniRecord
	case 14:
		generateFunc = generateMidRecord
	case 15:
		generateFunc = generateRichRecord
	default:
		return nil, fmt.Errorf("unsupported logN value: %d. Supported values: 13, 14, 15", logN)
	}

	// 4. Generating records based on the logN parameter
	for i := 0; i < n; i++ {
		recBytes, err := generateFunc(i, maxJsonLength, n)
		if err != nil {
			return nil, fmt.Errorf("failed to generate record %d: %w", i, err)
		}
		if len(recBytes) > maxJsonLength {
			log.Printf("[WARN] Record %d for logN %d exceeded max length. Got: %d, Max: %d", i, logN, len(recBytes), maxJsonLength)
		} else if len(recBytes) < maxJsonLength-8 {
			log.Printf("[WARN] Record %d for logN %d is too small. Got: %d, Max: %d", i, logN, len(recBytes), maxJsonLength)
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

	if utils.ShouldPrintDebug(i, total) {
		fmt.Printf("[DBG] RichRecord[%03d]: baseSize=%d, remaining=%d (maxJsonLen=%d)\n",
			i, baseSize, remaining, maxJsonLength)
	}

	if remaining < 0 {
		return nil, fmt.Errorf("maxJsonLength %d is too small for a rich record (base size %d + hashes)", maxJsonLength, baseSize)
	}

	md5Len := 32
	shaLen := 64

	finalRec := CTIRecordRich{
		MD5:           utils.FakeHash("md5", i, md5Len),
		SHA256:        utils.FakeHash("sha", i, shaLen),
		MalwareClass:  baseRec.MalwareClass,
		MalwareFamily: baseRec.MalwareFamily,
		AVDetects:     baseRec.AVDetects,
		ThreatLevel:   baseRec.ThreatLevel,
		Padding:       utils.FakeHash("pad", i, remaining),
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
	remaining := maxJsonLength -
		baseSize -
		32 - // MD5
		16 - // SHA256 short
		15 // json overhead (quotes, commas, braces)

	if utils.ShouldPrintDebug(i, total) {
		fmt.Printf("[DBG] MidRecord[%03d]: baseSize=%d, remaining=%d (maxJsonLen=%d)\n",
			i, baseSize, remaining, maxJsonLength)
	}

	if remaining < 0 {
		return nil, fmt.Errorf("maxJsonLength %d is too small for a mid record (base size %d + hashes)", maxJsonLength, baseSize)
	}

	md5Len := 32
	shaShortLen := 16

	finalRec := CTIRecordMid{
		MD5:           utils.FakeHash("md5", i, md5Len),
		SHA256Short:   utils.FakeHash("sha_short", i, shaShortLen),
		MalwareClass:  baseRec.MalwareClass,
		MalwareFamily: baseRec.MalwareFamily,
		AVDetects:     baseRec.AVDetects,
		ThreatLevel:   baseRec.ThreatLevel,
		Padding:       utils.FakeHash("pad", i, remaining),
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

	if utils.ShouldPrintDebug(i, total) {
		fmt.Printf("[DBG] MiniRecord[%03d]: baseSize=%d, remaining=%d (maxJsonLen=%d)\n",
			i, baseSize, remaining, maxJsonLength)
	}

	if remaining < 0 {
		return nil, fmt.Errorf("maxJsonLength %d is too small for a mini record (base size %d + md5)", maxJsonLength, baseSize)
	}

	md5Len := 32

	finalRec := CTIRecordMini{
		MD5:           utils.FakeHash("md5", i, md5Len),
		MalwareFamily: baseRec.MalwareFamily,
		ThreatLevel:   baseRec.ThreatLevel,
		Padding:       utils.FakeHash("pad", i, remaining),
	}
	recBytes, err := json.Marshal(finalRec)
	if err != nil {
		return nil, err
	}
	return recBytes, nil
}
