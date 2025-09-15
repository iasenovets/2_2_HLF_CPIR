// internal/fabgw/fabgw.go
package fabgw

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NewConnection creates a TLS-authenticated gRPC connection to a Fabric peer.
func NewConnection(peerEndpoint, tlsCACertPath, serverName string) (*grpc.ClientConn, error) {
	caPEM, err := os.ReadFile(tlsCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA: %w", err)
	}
	caCert, err := identity.CertificateFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS CA: %w", err)
	}

	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	creds := credentials.NewClientTLSFromCert(cp, serverName)
	conn, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", peerEndpoint, err)
	}
	return conn, nil
}

// NewIdentityFromDir loads the first cert in certDir and returns an X.509 identity.
func NewIdentityFromDir(mspID, certDir string) (*identity.X509Identity, error) {
	certPEM, err := readFirst(certDir)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		return nil, fmt.Errorf("new identity: %w", err)
	}
	return id, nil
}

// NewSignerFromKeyDir loads the first key in keyDir and returns a signing function.
func NewSignerFromKeyDir(keyDir string) (identity.Sign, error) {
	keyPEM, err := readFirst(keyDir)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	privKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(privKey)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	return sign, nil
}

// readFirst returns the contents of the first file in a directory.
func readFirst(dir string) ([]byte, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, fmt.Errorf("no files in %s", dir)
	}
	return os.ReadFile(filepath.Join(dir, ents[0].Name()))
}

// Must is a tiny helper to panic on error with context.
func Must(err error, msg string) {
	if err != nil {
		panic(fmt.Errorf("%s: %w", msg, err))
	}
}
