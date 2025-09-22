package main

import (
	"fmt"
	"strconv"

	"off-chain-cpir/internal/cpir"
	"off-chain-cpir/internal/utils"
)

/********* main demo **********************************************/
func main() {
	//const dbSize = 100
	const idx = 13

	// HE keys
	params, sk, pk, _ := cpir.GenKeys()

	// --- Init --- numRecords | maxJSONlength | channel_name
	utils.Call("InitLedger", "73", "128", "channel_mid")

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
	dbSize, err := strconv.Atoi(totalStr)
	if err != nil {
		panic(fmt.Errorf("PublicQueryALL returned non-number %q: %w", totalStr, err))
	}

	fmt.Printf("CTI record count = %d\n", dbSize)

	// --- PIR
	encQueryB64, len_ct_bytes, _ := cpir.EncryptQueryBase64(params, pk, idx, dbSize, slotsPerRec)
	fmt.Printf("len_ct_bytes=%d\n", len_ct_bytes)

	encResB64, _ := utils.Call("PIRQuery", encQueryB64)
	dec, _ := cpir.DecryptResult(params, sk, encResB64, idx, dbSize, slotsPerRec)
	fmt.Println("PIR result =", dec.JSONString)
}
