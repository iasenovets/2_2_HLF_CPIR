// test_pir_client.go
package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ----------------------------------------------------------
// Configuration: adjust these paths to match your fablo-target
// ----------------------------------------------------------

const (
	mspID         = "Org1MSP"
	cryptoPath    = "fablo-target/crypto/peerOrganizations/org1.example.com"
	certPath      = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyDir        = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath   = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint  = "localhost:7051"
	gatewayPeer   = "peer0.org1.example.com"
	channelName   = "my-channel1"
	chaincodeName = "test_pir"
)

func main() {
	// 0) Set up HE keys & parameters for PIR
	const dbSize = 100
	const targetIndex = 42

	params, sk, pk, err := GenKeys()
	if err != nil {
		panic(fmt.Errorf("HE keygen failed: %w", err))
	}

	// 1) Connect to Fabric Gateway over gRPC
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	id := newIdentity()
	sign := newSign()

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(fmt.Errorf("failed to connect to gateway: %w", err))
	}
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// 2) InitLedger (only needed once)
	fmt.Println("\n--> Submit Transaction: InitLedger")
	_, err = contract.SubmitTransaction("InitLedger")
	if err != nil {
		panic(fmt.Errorf("InitLedger failed: %w", err))
	}
	fmt.Println("*** InitLedger committed")

	// 3) Plaintext queries
	fmt.Println("\n--> Evaluate Transaction: PublicQuery(record000)")
	qRes, err := contract.EvaluateTransaction("PublicQuery", "record000")
	if err != nil {
		panic(fmt.Errorf("PublicQuery failed: %w", err))
	}
	fmt.Println("*** PublicQuery result:", string(qRes))

	fmt.Println("\n--> Evaluate Transaction: PublicQueryALL")
	allRes, err := contract.EvaluateTransaction("PublicQueryALL")
	if err != nil {
		panic(fmt.Errorf("PublicQueryALL failed: %w", err))
	}
	fmt.Println("*** Total CTI records:", string(allRes))

	// 4) Private Information Retrieval
	fmt.Println("\n--> Encrypting PIR query for index", targetIndex)
	encQueryB64, err := EncryptQueryBase64(params, pk, targetIndex, dbSize)
	if err != nil {
		panic(fmt.Errorf("EncryptQuery failed: %w", err))
	}

	fmt.Println("\n--> Evaluate Transaction: PIRQuery (homomorphic)")
	encResB64Bytes, err := contract.EvaluateTransaction("PIRQuery", encQueryB64)
	if err != nil {
		// unwrap Gateway errors if you like...
		panic(fmt.Errorf("PIRQuery failed: %w", err))
	}
	encResB64 := string(encResB64Bytes)
	fmt.Printf("*** Encrypted response (B64 len=%d)\n", len(encResB64))

	fmt.Println("\n--> Decrypting PIR result")
	decoded, err := DecryptResult(params, sk, encResB64, targetIndex, dbSize, 1)
	if err != nil {
		panic(fmt.Errorf("DecryptResult failed: %w", err))
	}
	fmt.Println("*** PIR decrypted value (IntValue) =", decoded.IntValue)
}

// newGrpcConnection creates a gRPC connection to the peer
func newGrpcConnection() *grpc.ClientConn {
	certPEM, err := ioutil.ReadFile(tlsCertPath)
	if err != nil {
		panic(fmt.Errorf("failed to read TLS certificate: %w", err))
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	transportCreds := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	conn, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCreds))
	if err != nil {
		panic(fmt.Errorf("failed to dial gRPC: %w", err))
	}
	return conn
}

// newIdentity creates a Fabric identity from an X.509 certificate
func newIdentity() *identity.X509Identity {
	certPEM, err := readFirstFile(certPath)
	if err != nil {
		panic(fmt.Errorf("failed to read certificate: %w", err))
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		panic(err)
	}
	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		panic(err)
	}
	return id
}

// newSign returns a signing function using the private key
func newSign() identity.Sign {
	keyPEM, err := readFirstFile(keyDir)
	if err != nil {
		panic(fmt.Errorf("failed to read private key: %w", err))
	}
	privKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		panic(err)
	}
	sign, err := identity.NewPrivateKeySign(privKey)
	if err != nil {
		panic(err)
	}
	return sign
}

// readFirstFile reads the first file in a directory
func readFirstFile(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no files in dir %s", dir)
	}
	return os.ReadFile(path.Join(dir, entries[0].Name()))
}
