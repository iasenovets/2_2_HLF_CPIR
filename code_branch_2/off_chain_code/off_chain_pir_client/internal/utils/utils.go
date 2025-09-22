package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

/********* REST helpers *******************************************/
func Call(method string, args ...string) (string, error) {
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
