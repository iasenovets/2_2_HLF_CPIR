package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func invokeChaincode(baseURL, token, method string, args []string) ([]byte, error) {
	payload := map[string]interface{}{
		"method": method,
		"args":   args,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", baseURL+"/invoke/my-channel1/test_pir", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

/*
// === PIR Functions ===
func encryptQuery(index, dbSize int, params bgv.Parameters, pk *rlwe.PublicKey) ([]byte, error) {
	vec := make([]uint64, dbSize)
	vec[index] = 1 // one-hot encoding

	encoder := bgv.NewEncoder(params)
	pt := bgv.NewPlaintext(params)
	encoder.EncodeUint(vec, pt)

	encryptor := bgv.NewEncryptor(params, pk)
	ct := encryptor.EncryptNew(pt)
	return ct.MarshalBinary()
}

func decryptResult(encResultBytes []byte, params bgv.Parameters, sk *rlwe.SecretKey) ([]uint64, error) {
	ct := new(rlwe.Ciphertext)
	if err := ct.UnmarshalBinary(encResultBytes); err != nil {
		return nil, err
	}
	decr := bgv.NewDecryptor(params, sk)
	pt := decr.DecryptNew(ct)
	encoder := bgv.NewEncoder(params)
	return encoder.DecodeUint(pt), nil
}
*/

func main() {

	// ---- 0. Initial Setup ----
	baseURL := "http://localhost:8801"
	const dbSize = 100
	const targetIndex = 42

	params, sk, pk, err := GenKeys()
	if err != nil {
		panic(err)
	}

	// ---------- 1. Enrolling User and Testing API ----------
	// 1.1 Enroll Admin
	adminToken, err := enrollUser(baseURL, "admin", "adminpw")
	if err != nil {
		panic("Admin enrollment failed: " + err.Error())
	}
	fmt.Println("Admin enrolled. Token:", adminToken)

	// 1.2 Register User
	if err := registerUser(baseURL, adminToken, "user123", "secret123"); err != nil {
		panic("User registration failed: " + err.Error())
	}
	fmt.Println("User registered.")

	// 1.3 Enroll user
	userToken, err := enrollUser(baseURL, "user123", "secret123")
	if err != nil {
		panic("User enrollment failed: " + err.Error())
	}

	// 1.4 Invoke initLedger
	if _, err := invokeChaincode(baseURL, userToken, "InitLedger", []string{}); err != nil {
		panic("InitLedger failed: " + err.Error())
	}
	fmt.Println("Ledger initialized.")

	// 1.5 Query single CTI
	if res, err := invokeChaincode(baseURL, userToken, "PublicQueryCTI", []string{"record000"}); err != nil {
		panic("Query CTI failed: " + err.Error())
	} else {
		fmt.Println("Queried CTI Record:", string(res))
	}

	// 1.6 Query all CTI count
	if res, err := invokeChaincode(baseURL, userToken, "PublicQueryALL", []string{}); err != nil {
		panic("Query all failed: " + err.Error())
	} else {
		fmt.Println("Total CTI records:", string(res))
	}

	// ---------- 2. Enrolling User and Testing API ----------

	// 2.1 Encrypt a PIR Query for record #42
	encQueryB64, err := EncryptQueryBase64(params, pk, targetIndex, dbSize)
	if err != nil {
		panic("Query encryption failed: " + err.Error())
	}

	// 2.2 Send PIR Query
	resBytes, err := invokeChaincode(baseURL, userToken, "PIRQuery", []string{encQueryB64})
	if err != nil {
		panic(err)
	}

	/* ---------- unwrap REST reply ---------- */
	var wrap struct {
		Response string `json:"response"` // on success
		Error    string `json:"error"`    // on chaincode failure
	}
	fmt.Printf("[HTTP] %s\n", resBytes)
	if err := json.Unmarshal(resBytes, &wrap); err != nil {
		panic("proxy returned non-JSON (HTML?)\n" + string(resBytes))
	}
	if wrap.Error != "" {
		panic("chaincode error: " + wrap.Error)
	}
	encResultB64 := wrap.Response
	if encResultB64 == "" {
		panic("empty response from proxy")
	}

	// 2.3 Decrypt result
	out, err := DecryptResult(params, sk, encResultB64, targetIndex, dbSize, 1 /*slotsPerRecord*/)
	if err != nil {
		panic(err)
	}
	fmt.Println("Record value =", out.IntValue)
}
