package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// CTIRecord represents a single CTI record structure
type CTIRecord struct {
	MD5           string `json:"md5"`
	SHA256        string `json:"sha256"`
	MalwareClass  string `json:"malware_class"`
	MalwareFamily string `json:"malware_family"`
	AVDetects     int    `json:"av_detects"`
	ThreatLevel   string `json:"threat_level"`
}

// SmartContract provides functions for managing CTI records
type SmartContract struct {
	contractapi.Contract
}

// InitLedger initializes the ledger with 100 CTI records
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	for i := 0; i < 100; i++ {
		record := CTIRecord{
			MD5:           fmt.Sprintf("md5-hash-%d", i),
			SHA256:        fmt.Sprintf("sha256-hash-%d", i),
			MalwareClass:  "Trojan",
			MalwareFamily: fmt.Sprintf("Family-%d", i),
			AVDetects:     i % 10,
			ThreatLevel:   "Medium",
		}

		recordBytes, _ := json.Marshal(record)
		ctx.GetStub().PutState(strconv.Itoa(i), recordBytes)
	}
	return nil
}

// AddCTI adds a new CTI record to the ledger
func (s *SmartContract) AddCTI(ctx contractapi.TransactionContextInterface, index int, md5, sha256, malwareClass, malwareFamily string, avDetects int, threatLevel string) error {
	record := CTIRecord{
		MD5:           md5,
		SHA256:        sha256,
		MalwareClass:  malwareClass,
		MalwareFamily: malwareFamily,
		AVDetects:     avDetects,
		ThreatLevel:   threatLevel,
	}
	recordBytes, _ := json.Marshal(record)
	return ctx.GetStub().PutState(strconv.Itoa(index), recordBytes)
}

// PublicQueryCTI returns a single CTI record by index
func (s *SmartContract) PublicQueryCTI(ctx contractapi.TransactionContextInterface, index int) (*CTIRecord, error) {
	recordBytes, err := ctx.GetStub().GetState(strconv.Itoa(index))
	if err != nil || recordBytes == nil {
		return nil, fmt.Errorf("record %d not found", index)
	}
	var record CTIRecord
	json.Unmarshal(recordBytes, &record)
	return &record, nil
}

// PublicQueryALL returns the total number of CTI records
func (s *SmartContract) PublicQueryALL(ctx contractapi.TransactionContextInterface) (int, error) {
	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return 0, err
	}
	defer iterator.Close()

	count := 0
	for iterator.HasNext() {
		iterator.Next()
		count++
	}
	return count, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		panic(fmt.Sprintf("Error creating chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting chaincode: %v", err))
	}
}
