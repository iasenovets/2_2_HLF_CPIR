package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

/********* REST helpers *******************************************/
func call(method string, args ...string) (string, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"method": method, "args": args,
	})
	resp, err := http.Post("http://localhost:8080/invoke",
		"application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	all, _ := io.ReadAll(resp.Body)

	var wrap struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(all, &wrap); err != nil {
		return "", err
	}
	if wrap.Error != "" {
		return "", fmt.Errorf("%s", wrap.Error)
	}
	return wrap.Response, nil
}

/********* main demo **********************************************/
func main() {
	//const dbSize = 100
	const idx = 13

	// HE keys
	params, sk, pk, _ := GenKeys()

	// --- Init --- numRecords | maxJSONlength | channel_name
	call("InitLedger", "64", "128", "channel_mini")

	slotsStr, _ := call("GetSlotsPerRecord")
	slotsPerRec, _ := strconv.Atoi(slotsStr)
	fmt.Println("slotsPerRec =", slotsPerRec)

	// --- Public query
	j, _ := call("PublicQueryCTI", "record000")
	fmt.Println("record000 =", j)

	totalStr, err := call("PublicQueryALL")
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
	encQueryB64, len_ct_bytes, _ := EncryptQueryBase64(params, pk, idx, dbSize, slotsPerRec)
	fmt.Printf("len_ct_bytes=%d\n", len_ct_bytes)

	encResB64, _ := call("PIRQuery", encQueryB64)
	dec, _ := DecryptResult(params, sk, encResB64, idx, dbSize, slotsPerRec)
	fmt.Println("PIR result =", dec.JSONString)
}
