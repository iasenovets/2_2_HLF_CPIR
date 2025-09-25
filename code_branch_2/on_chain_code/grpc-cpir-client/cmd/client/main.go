// test_pir_client.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"grpc-cpir/internal/cpir"
	"grpc-cpir/internal/fabgw"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
)

// ----------------------------------------------------------
// Configuration
// ----------------------------------------------------------

var (
	// compile-time constants are fine here
	mspID         = "Org1MSP"
	peerEndpoint  = "localhost:7041"
	gatewayPeer   = "peer0.org1.example.com"
	channelName   = "channel-mini"
	chaincodeName = "channel_mini_cpir"

	// to be filled at runtime in init()
	cryptoPath  string
	certPath    string
	keyDir      string
	tlsCertPath string
)

var meta struct {
	NumRecords  int `json:"numRecords"`
	SlotsPerRec int `json:"slotsPerRec"`
}

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot resolve home dir: %v", err)
	}

	// Build paths at runtime (no ~)
	cryptoPath = filepath.Join(
		home,
		"fablo_test", "fablo-target", "fabric-config", "crypto-config",
		"peerOrganizations", "org1.example.com",
	)
	certPath = filepath.Join(cryptoPath, "users", "User1@org1.example.com", "msp", "signcerts")
	keyDir = filepath.Join(cryptoPath, "users", "User1@org1.example.com", "msp", "keystore")
	tlsCertPath = filepath.Join(cryptoPath, "peers", "peer0.org1.example.com", "tls", "ca.crt")
}

func main() {
	log.Println("MSP:", mspID)
	log.Println("cryptoPath:", cryptoPath)
	log.Println("certPath:", certPath)
	log.Println("keyDir:", keyDir)
	log.Println("tlsCertPath:", tlsCertPath)
	log.Println("peerEndpoint:", peerEndpoint)

	// 0) HE keys
	params, sk, pk, err := cpir.GenKeys()
	fabgw.Must(err, "HE keygen failed")

	// 1) Fabric Gateway connection (TLS + identity + signer)
	conn, err := fabgw.NewConnection(peerEndpoint, tlsCertPath, gatewayPeer)
	fabgw.Must(err, "dial gateway")
	defer conn.Close()

	id, err := fabgw.NewIdentityFromDir(mspID, certPath)
	fabgw.Must(err, "load identity")

	sign, err := fabgw.NewSignerFromKeyDir(keyDir)
	fabgw.Must(err, "load signer")

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	fabgw.Must(err, "connect gateway")
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// 2) Client 1: Init ledger with sample data (pick params that fit logN=13 capacity)
	fmt.Println("\n--> Submit Transaction: InitLedger")
	_, err = contract.SubmitTransaction("InitLedger", "32", "224") // or "64","128"
	fabgw.Must(err, "InitLedger failed")
	fmt.Println("*** InitLedger committed")

	// 3) Client 2: Discovers metadata parameters
	fmt.Println("\n--> Evaluate Transaction: GetMetadata")

	metaRaw, err := contract.EvaluateTransaction("GetMetadata")
	fabgw.Must(err, "GetMetadata failed")

	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		fabgw.Must(err, "failed to parse GetMetadata JSON")
	}
	dbSize := meta.NumRecords
	slotsPerRec := meta.SlotsPerRec

	fmt.Printf("*** dbSize = %d\n", dbSize)
	fmt.Printf("*** slotsPerRec = %d\n", slotsPerRec)

	// Optional sanity read
	fmt.Println("\n--> Evaluate Transaction: PublicQueryCTI(record013)")
	qRes, err := contract.EvaluateTransaction("PublicQueryCTI", "record013")
	fabgw.Must(err, "PublicQueryCTI failed")
	fmt.Println("*** record013 =", string(qRes))

	fmt.Println("\n--> Evaluate Transaction: PublicQueryCTIWithAudit(record013)")
	qResAudit, err := contract.SubmitTransaction("PublicQueryCTIWithAudit", "record013")
	fabgw.Must(err, "PublicQueryCTI failed")
	fmt.Println("*** record013 =", string(qResAudit))

	// 4) CPIR: encrypt → evaluate → decrypt
	const targetIndex = 13
	fmt.Println("\n--> Encrypting PIR query for index", targetIndex)
	encQueryB64, _, err := cpir.EncryptQueryBase64(params, pk, targetIndex, dbSize, slotsPerRec)
	fabgw.Must(err, "EncryptQueryBase64 failed")

	fmt.Println("\n--> Evaluate Transaction: PIRQuery")
	encResB64Bytes, err := contract.EvaluateTransaction("PIRQuery", encQueryB64)
	fabgw.Must(err, "PIRQuery failed")

	// Audited read (committed audit record):
	encResAudited, err := contract.SubmitTransaction("PIRQueryWithAudit", encQueryB64)
	fabgw.Must(err, "PIRQuery failed")

	encResB64 := string(encResB64Bytes)
	encResAuditedB64 := string(encResAudited)

	fmt.Printf("*** Encrypted response (B64 len=%d)\n", len(encResB64))
	fmt.Printf("*** Encrypted response audited (B64 len=%d)\n", len(encResAuditedB64))

	fmt.Println("\n--> Decrypting PIR result")
	decoded, err := cpir.DecryptResult(params, sk, encResB64, targetIndex, dbSize, slotsPerRec)
	fabgw.Must(err, "DecryptResult failed")
	fmt.Println("*** PIR JSON =", decoded.JSONString)
}
