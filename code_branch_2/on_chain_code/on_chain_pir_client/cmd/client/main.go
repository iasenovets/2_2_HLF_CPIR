// test_pir_client.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"on-chain-pir-client/internal/cpir"
	"on-chain-pir-client/internal/fabgw"

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

	// --- Set parameters --- Please follow the Feasible Parameters table in the README.md
	const dbSize = 64         // set the total number of records in the DB: 100, 256, or 512 (necessary param)
	const maxJSONlength = 128 // set the max JSON length: 64, 128, 224, 256, 384, or 512 (necessary param)
	const logN = ""           // set the HE parameter LogN: 13, 14, or 15
	const logQi = ""          // set the HE parameter logQi as JSON array, or "" to use default (optional param)
	const logPi = ""          // set the HE parameter logPi as JSON array, or "" to use default (optional param)
	const t = ""              // set the HE parameter plaintext modulus t, or 0 to use default (optional param)
	const targetIndex = 13    // set the index of the record to be retrieved: 0..dbSize-1 (necessary param)

	// 1) Client 1: Init ledger with sample data (pick params that fit logN=13 capacity)
	fmt.Println("\n--> Submit Transaction: InitLedger")
	// pass: n, maxJSON, logN="", logQi="[]", logPi="[]", t=""
	_, err = contract.SubmitTransaction("InitLedger",
		fmt.Sprintf("%d", dbSize),
		fmt.Sprintf("%d", maxJSONlength),
		fmt.Sprintf("%d", logN),
		logQi,
		logPi,
		t)
	//_, err = contract.SubmitTransaction("InitLedger", "32", "224", "", "[]", "[]", "")
	fabgw.Must(err, "InitLedger failed")

	fmt.Println("*** InitLedger committed")

	// 2) Client 2: Discovers metadata parameters
	fmt.Println("\n--> Evaluate Transaction: GetMetadata")
	metaRaw, err := contract.EvaluateTransaction("GetMetadata")
	fabgw.Must(err, "GetMetadata failed")

	var meta cpir.Metadata
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		fabgw.Must(err, "failed to parse GetMetadata JSON")
	}

	fmt.Printf("*** n=%d  s=%d  logN=%d  N=%d  t=%d  logQi=%v  logPi=%v\n",
		meta.NRecords, meta.RecordS, meta.LogN, meta.N, meta.T, meta.LogQi, meta.LogPi)

	// 3) Client 2: Build HE params/keys from server metadata (parity with off-chain)
	params, sk, pk, err := cpir.GenKeysFromMetadata(meta)
	fabgw.Must(err, "GenKeysFromMetadata failed")

	serverDbSize := meta.NRecords
	slotsPerRec := meta.RecordS

	fmt.Printf("*** serverDbSize = %d\n", serverDbSize)
	fmt.Printf("*** slotsPerRec = %d\n", slotsPerRec)

	// Optional sanity read
	fmt.Println("\n--> Evaluate Transaction: PublicQuery(record013)")
	qRes, err := contract.EvaluateTransaction("PublicQuery", "record013")
	fabgw.Must(err, "PublicQuery failed")
	fmt.Println("*** record013 =", string(qRes))

	fmt.Println("\n--> Evaluate Transaction: PublicQuerySubmit(record013)")
	qResAudit, err := contract.SubmitTransaction("PublicQuerySubmit", "record013")
	fabgw.Must(err, "PublicQuery failed")
	fmt.Println("*** record013 =", string(qResAudit))

	// 4) Client 2: CPIR: encrypt → evaluate → decrypt
	fmt.Println("\n--> Encrypting PIR query for index", targetIndex)
	encQueryB64, _, err := cpir.EncryptQueryBase64(params, pk, targetIndex, serverDbSize, slotsPerRec)
	fabgw.Must(err, "EncryptQueryBase64 failed")

	fmt.Println("\n--> Evaluate Transaction: PIRQuery")
	encResB64Bytes, err := contract.EvaluateTransaction("PIRQuery", encQueryB64)
	fabgw.Must(err, "PIRQuery failed")

	fmt.Println("\n--> Submit Transaction: PIRQuerySubmit")
	encResAudited, err := contract.SubmitTransaction("PIRQuerySubmit", encQueryB64)
	fabgw.Must(err, "PIRQuerySubmit failed")

	encResB64 := string(encResB64Bytes)
	encResAuditedB64 := string(encResAudited)
	fmt.Printf("*** Encrypted response (B64 len=%d)\n", len(encResB64))
	fmt.Printf("*** Encrypted response (audited) (B64 len=%d)\n", len(encResAuditedB64))

	fmt.Println("\n--> Decrypting PIR result")
	decoded, err := cpir.DecryptResult(params, sk, encResB64, targetIndex, serverDbSize, slotsPerRec)
	fabgw.Must(err, "DecryptResult failed")
	fmt.Println("*** PIR JSON =", decoded.JSONString)

}
