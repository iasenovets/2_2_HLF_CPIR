package main

import (
	"fmt"
	"strconv"

	"off-chain-pir-client/internal/cpir"
	"off-chain-pir-client/internal/utils"
)

/********* main demo **********************************************/
func main() {
	// --- Set parameters --- Please follow the Feasible Parameters table in the README.md
	const logN = 13          // set the HE parameter LogN: 13, 14, or 15
	const dbSize = 128       // set the total number of records in the DB: 100, 256, or 512
	const maxJSONlength = 64 // set the max JSON length: 64, 128, 224, 256, 384, or 512
	const idx = 13           // set the index of the record to be retrieved: 0..dbSize-1
	fmt.Printf("Demo with LogN=%d, dbSize=%d, maxJSONlength=%d, retrieving record idx=%d\n", logN, dbSize, maxJSONlength, idx)

	// HE keys
	params, sk, pk, _ := cpir.GenKeys(logN)

	// --- Init --- dbSize | maxJSONlength | logN
	utils.Call("InitLedger", fmt.Sprintf("%d", dbSize), fmt.Sprintf("%d", maxJSONlength), fmt.Sprintf("%d", logN))

	slotsStr, _ := utils.Call("GetSlotsPerRecord")
	slotsPerRec, _ := strconv.Atoi(slotsStr)
	fmt.Println("slotsPerRec =", slotsPerRec)

	// --- Public query
	j, _ := utils.Call("PublicQueryCTI", "record000")
	fmt.Println("record000 =", j)

	totalStr, err := utils.Call("PublicQueryALL")
	if err != nil {
		panic(err)
	}
	fmt.Println("Total CTI records =", totalStr)
	serverDbSize, err := strconv.Atoi(totalStr)
	if err != nil {
		panic(fmt.Errorf("PublicQueryALL returned non-number %q: %w", totalStr, err))
	}

	fmt.Printf("CTI record count = %d\n", serverDbSize)

	// --- PIR
	encQueryB64, len_ct_bytes, _ := cpir.EncryptQueryBase64(params, pk, idx, serverDbSize, slotsPerRec)
	fmt.Printf("len_ct_bytes=%d\n", len_ct_bytes)

	encResB64, _ := utils.Call("PIRQuery", encQueryB64)
	dec, _ := cpir.DecryptResult(params, sk, encResB64, idx, serverDbSize, slotsPerRec)
	fmt.Println("PIR result =", dec.JSONString)
}
