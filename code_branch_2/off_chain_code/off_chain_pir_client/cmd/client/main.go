package main

import (
	"encoding/json"
	"fmt"

	"off-chain-pir-client/internal/cpir"
	"off-chain-pir-client/internal/utils"
)

/********* main demo **********************************************/
func main() {
	const logN = 13
	const dbSize = 64
	const maxJSONlength = 128
	const idx = 13

	fmt.Printf("Demo with LogN=%d, dbSize=%d, maxJSONlength=%d, retrieving record idx=%d\n",
		logN, dbSize, maxJSONlength, idx)

	// 1) Init (any client)
	utils.Call("InitLedger",
		fmt.Sprintf("%d", dbSize),
		fmt.Sprintf("%d", maxJSONlength),
		fmt.Sprintf("%d", logN),
	)

	// 2) Discover metadata (single JSON)
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

	// 4) Generate keys from literal (matches server params)
	params, sk, pk, err := cpir.GenKeysFromMetadata(meta)
	if err != nil {
		panic(fmt.Errorf("GenKeysFromLiteral failed: %w", err))
	}
	fmt.Printf("KeyGen done: skID=%p  pkID=%p\n", sk, pk)
	// 5) Public read example (unchanged)
	j, _ := utils.Call("PublicQueryCTI", "record000")
	fmt.Println("record000 =", j)

	// 6) PIR query using discovered n,s
	serverDbSize := meta.NRecords
	slotsPerRec := meta.RecordS

	encQueryB64, lenCtBytes, _ := cpir.EncryptQueryBase64(params, pk, idx, serverDbSize, slotsPerRec)
	fmt.Printf("len_ct_bytes=%d\n", lenCtBytes)

	encResB64, _ := utils.Call("PIRQuery", encQueryB64)
	dec, _ := cpir.DecryptResult(params, sk, encResB64, idx, serverDbSize, slotsPerRec)
	fmt.Println("PIR result =", dec.JSONString)
}
