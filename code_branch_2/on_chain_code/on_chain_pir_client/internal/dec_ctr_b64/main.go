package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"on-chain-pir-client/internal/cpir"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	"log"
)

func main() {
	const filePath = "enc_res.b64"
	const dbSize = 128
	const slotsPerRecord = 256
	const logN = 15
	const targetIndex = 13

	meta := cpir.Metadata{
		NRecords: dbSize,
		RecordS:  slotsPerRecord,
		LogN:     logN,
		N:        32768,
		T:        65537,
		LogQi:    []int{54},
		LogPi:    []int{54},
	}

	params, sk, _, err := cpir.GenKeysFromMetadata(meta)
	if err != nil {
		log.Fatalf("GenKeysFromMetadata failed: %v", err)
	}

	fmt.Printf("[INFO] Using mock params: LogN=%d, NRecords=%d\n", meta.LogN, meta.NRecords)

	decoded, err := decryptFile(params, sk, filePath, targetIndex, dbSize, slotsPerRecord)
	if err != nil {
		log.Fatalf("decryptFile failed: %v", err)
	}

	fmt.Println("*** Decrypted JSON:", decoded.JSONString)
}

// decryptFile reads a Base64-encoded ciphertext from disk and decrypts it
// using the provided BGV params and secret key. It returns the Decoded struct
// with JSON or integer value, depending on slotsPerRecord.
func decryptFile(params bgv.Parameters, sk *rlwe.SecretKey,
	filePath string, index, dbSize, slotsPerRecord int) (cpir.Decoded, error) {

	var out cpir.Decoded

	fmt.Printf("[INFO] Reading encrypted PIR result from %s\n", filePath)

	// 1. Read ciphertext from file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return out, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	// Trim newlines if needed
	encResB64 := string(data)
	encResB64 = trimB64(encResB64)
	if encResB64 == "" {
		return out, fmt.Errorf("PIRQuery: empty encResB64")
	}
	fmt.Printf("Received encResB64 length: %d\n", len(encResB64))
	fmt.Printf("First 100 chars: %s\n", encResB64[:min(100, len(encResB64))])
	fmt.Printf("[INFO] Loaded ciphertext (Base64 len=%d)\n", len(encResB64))

	// 2. Optional sanity check: confirm it's valid Base64
	if _, err := base64.StdEncoding.DecodeString(encResB64); err != nil {
		return out, fmt.Errorf("invalid Base64 ciphertext: %w", err)
	}

	// 3. Delegate to cpir.DecryptResult
	fmt.Println("[INFO] Decrypting PIR result...")
	out, err = cpir.DecryptResult(params, sk, encResB64, index, dbSize, slotsPerRecord)
	if err != nil {
		return out, fmt.Errorf("DecryptResult failed: %w", err)
	}

	if out.JSONString != "" {
		fmt.Printf("[OK] Decrypted JSON = %s\n", out.JSONString)
	} else {
		fmt.Printf("[OK] Decrypted integer value = %d\n", out.IntValue)
	}

	return out, nil
}

// trimB64 removes accidental whitespace or trailing newlines
func trimB64(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
