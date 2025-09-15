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

	req, _ := http.NewRequest("POST", baseURL+"/invoke/my-channel1/test_api", bytes.NewBuffer(body))
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

func main() {
	baseURL := "http://localhost:8801"

	// 1. Enroll Admin
	adminToken, err := enrollUser(baseURL, "admin", "adminpw")
	if err != nil {
		panic("Admin enrollment failed: " + err.Error())
	}
	fmt.Println("Admin enrolled. Token:", adminToken)

	// 2. Register User
	if err := registerUser(baseURL, adminToken, "user123", "secret123"); err != nil {
		panic("User registration failed: " + err.Error())
	}
	fmt.Println("User registered.")

	// 3. Enroll User
	userToken, err := enrollUser(baseURL, "user123", "secret123")
	if err != nil {
		panic("User enrollment failed: " + err.Error())
	}
	fmt.Println("User enrolled. Token:", userToken)

	// 4. Invoke initLedger
	if _, err := invokeChaincode(baseURL, userToken, "InitLedger", []string{}); err != nil {
		panic("InitLedger failed: " + err.Error())
	}
	fmt.Println("Ledger initialized.")

	// 5. Add CTI
	args := []string{"100", "md5-new", "sha256-new", "Worm", "TestFamily", "3", "High"}
	if _, err := invokeChaincode(baseURL, userToken, "AddCTI", args); err != nil {
		panic("AddCTI failed: " + err.Error())
	}
	fmt.Println("CTI added at index 100.")

	// 6. Query single CTI
	if res, err := invokeChaincode(baseURL, userToken, "PublicQueryCTI", []string{"100"}); err != nil {
		panic("Query CTI failed: " + err.Error())
	} else {
		fmt.Println("Queried CTI Record:", string(res))
	}

	// 7. Query all CTI count
	if res, err := invokeChaincode(baseURL, userToken, "PublicQueryALL", []string{}); err != nil {
		panic("Query all failed: " + err.Error())
	} else {
		fmt.Println("Total CTI records:", string(res))
	}
}
