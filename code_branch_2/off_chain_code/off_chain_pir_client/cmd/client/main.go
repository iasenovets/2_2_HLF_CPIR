package main

import (
	"encoding/json"
	"fmt"

	"off-chain-pir-client/internal/cpir"
	"off-chain-pir-client/internal/utils"
)

/********* main demo **********************************************/
func main() {
	// --- Set parameters --- Please follow the Feasible Parameters table in the README.md
	const dbSize = 128        // set the total number of records in the DB: 100, 256, or 512 (necessary param)
	const maxJSONlength = 256 // set the max JSON length: 64, 128, 224, 256, 384, or 512 (necessary param)
	const logN = ""           // set the HE parameter LogN: 13, 14, or 15
	const logQi = ""          // set the HE parameter logQi as JSON array, or "" to use default (optional param)
	const logPi = ""          // set the HE parameter logPi as JSON array, or "" to use default (optional param)
	const t = ""              // set the HE parameter plaintext modulus t, or 0 to use default (optional param)
	const targetIndex = 13    // set the index of the record to be retrieved: 0..dbSize-1 (necessary param)

	fmt.Println("\n--> Submit Transaction: InitLedger")
	// 1)  Client 1: Init ledger with sample data
	utils.Call("InitLedger",
		fmt.Sprintf("%d", dbSize),
		fmt.Sprintf("%d", maxJSONlength),
		logN,
		logQi,
		logPi,
		t,
		//
	)

	// 2) Client 2: Discovers metadata parameters  (single JSON)
	metaStr, _ := utils.Call("GetMetadata")
	var meta cpir.Metadata
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		panic(fmt.Errorf("failed to parse metadata: %w", err))
	}

	// Print each parameter (for debugging / parity checks)
	fmt.Println("---- GetMetadata ----")
	fmt.Printf("n         : %d\n", meta.NRecords)
	fmt.Printf("record_s  : %d\n", meta.RecordS)
	fmt.Printf("logN      : %d\n", meta.LogN)
	fmt.Printf("N         : %d\n", meta.N)
	fmt.Printf("t         : %d\n", meta.T)
	fmt.Printf("logQi     : %v\n", meta.LogQi)
	fmt.Printf("logPi     : %v\n", meta.LogPi)
	fmt.Println("---------------------")

	// 3) Client 2: KeyGen using discovered metadata
	params, sk, pk, err := cpir.GenKeysFromMetadata(meta)
	if err != nil {
		panic(fmt.Errorf("GenKeysFromLiteral failed: %w", err))
	}
	fmt.Printf("KeyGen done: skID=%p  pkID=%p\n", sk, pk)

	// Sanity check: fetch a public record (no encryption)
	j, _ := utils.Call("PublicQuery", "record013")
	fmt.Println("PublicQuery: record013 =", j)

	// 4) Client 2: CPIR: Encrypt → Evaluate → Decrypt
	serverDbSize := meta.NRecords
	slotsPerRec := meta.RecordS

	encQueryB64, lenCtBytes, _ := cpir.EncryptQueryBase64(params, pk, targetIndex, serverDbSize, slotsPerRec)
	fmt.Printf("len_ct_bytes=%d\n", lenCtBytes)

	encResB64, _ := utils.Call("PIRQuery", encQueryB64)
	dec, _ := cpir.DecryptResult(params, sk, encResB64, targetIndex, serverDbSize, slotsPerRec)
	fmt.Println("PIR result =", dec.JSONString)
}
