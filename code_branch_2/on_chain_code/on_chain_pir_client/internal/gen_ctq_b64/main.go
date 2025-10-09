// test_pir_client.go
package main

import (
	"fmt"
	"log"
	"os"

	"on-chain-pir-client/internal/cpir"
)

func main() {
	// --- Set parameters ---
	const dbSize = 128        // set the total number of records in the DB: 100, 256, or 512 (necessary param)
	const maxJSONlength = 256 // set the max JSON length: 64, 128, 224, 256, 384, or 512 (necessary param)
	const logN = 15           // set the HE parameter LogN: 13, 14, or 15
	//const logQi = ""          // set the HE parameter logQi as JSON array, or "" to use default (optional param)
	//const logPi = ""          // set the HE parameter logPi as JSON array, or "" to use default (optional param)
	//const t = ""              // set the HE parameter plaintext modulus t, or 0 to use default (optional param)
	const targetIndex = 13 // set the index of the record to be retrieved: 0..dbSize-1 (necessary param)

	// Create mock metadata since we're not calling the chaincode
	meta := cpir.Metadata{
		NRecords: dbSize,
		RecordS:  maxJSONlength, // Assuming 16 slots per record for maxJSONlength=128
		LogN:     logN,          // Default logN: 13,14,15
		N:        32768,         // 8192, 16384, 32768
		T:        65537,
		LogQi:    []int{54},
		LogPi:    []int{54},
	}

	fmt.Printf("*** Using mock metadata: n=%d  s=%d  logN=%d  N=%d  t=%d  logQi=%v  logPi=%v\n",
		meta.NRecords, meta.RecordS, meta.LogN, meta.N, meta.T, meta.LogQi, meta.LogPi)

	// Generate HE params/keys from metadata
	params, _, pk, err := cpir.GenKeysFromMetadata(meta)
	if err != nil {
		log.Fatalf("GenKeysFromMetadata failed: %v", err)
	}

	serverDbSize := meta.NRecords
	slotsPerRec := meta.RecordS

	fmt.Printf("*** serverDbSize = %d\n", serverDbSize)
	fmt.Printf("*** slotsPerRec = %d\n", slotsPerRec)

	// Generate encrypted query
	fmt.Println("\n--> Encrypting PIR query for index", targetIndex)
	encQueryB64, _, err := cpir.EncryptQueryBase64(params, pk, targetIndex, serverDbSize, slotsPerRec)
	if err != nil {
		log.Fatalf("EncryptQueryBase64 failed: %v", err)
	}

	// Save encQueryB64 to file
	fmt.Println("\n--> Saving encrypted query to enc.b64")
	err = os.WriteFile("enc.b64", []byte(encQueryB64), 0644)
	if err != nil {
		log.Fatalf("Failed to write enc.b64: %v", err)
	}

	fmt.Printf("*** Encrypted query saved to enc.b64 (length: %d bytes)\n", len(encQueryB64))
	fmt.Println("*** Done - No chaincode calls were made")
}
