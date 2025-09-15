// === file: auth.go ===
package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type AuthResponse struct {
	Token string `json:"token"`
}

func enrollUser(baseURL, id, secret string) (string, error) {
	payload := map[string]string{"id": id, "secret": secret}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(baseURL+"/user/enroll", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	var auth AuthResponse
	if err := json.Unmarshal(respBody, &auth); err != nil {
		return "", err
	}
	return auth.Token, nil
}

func registerUser(baseURL, adminToken, userID, userSecret string) error {
	payload := map[string]string{"id": userID, "secret": userSecret}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", baseURL+"/user/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
