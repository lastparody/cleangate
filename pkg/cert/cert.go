package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	caFileName  = "cleangate_ca.crt"
	keyFileName = "cleangate_ca.key"
)

// CertManager handles the Root CA and generating leaf certificates for MITM
type CertManager struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	tlsCfg *tls.Config
}

// InitCA loads the existing CA or generates a new one and installs it
func InitCA(dataDir string) (*CertManager, error) {
	caPath := filepath.Join(dataDir, caFileName)
	keyPath := filepath.Join(dataDir, keyFileName)

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey

	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		fmt.Println("Root CA not found, generating a new one...")
		caCert, caKey, err = generateCA(caPath, keyPath)
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Println("Loading existing Root CA...")
		caCert, caKey, err = loadCA(caPath, keyPath)
		if err != nil {
			return nil, err
		}
	}

	// Always check if the cert is trusted in Keychain and install if not
	if !isCertTrusted(caPath) {
		fmt.Println("Root CA is NOT trusted. Installing to macOS Keychain...")
		fmt.Println("You will be prompted for your macOS password.")
		err := installToKeychain(caPath)
		if err != nil {
			fmt.Printf("Failed to install to keychain (you can install manually: %s): %v\n", caPath, err)
		} else {
			fmt.Println("Successfully installed Root CA to Keychain!")
		}
	} else {
		fmt.Println("Root CA is already trusted in Keychain.")
	}

	cm := &CertManager{
		caCert: caCert,
		caKey:  caKey,
	}

	// Setup TLS Config for the proxy to dynamically generate certificates
	cm.tlsCfg = &tls.Config{
		GetCertificate: cm.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	return cm, nil
}

func (cm *CertManager) TLSConfig() *tls.Config {
	return cm.tlsCfg
}

// getCertificate is called by the TLS server to dynamically generate a cert for the requested domain (SNI)
func (cm *CertManager) getCertificate(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := helloInfo.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no SNI domain provided")
	}

	// In a production app, we should cache these generated certificates in memory to improve performance
	// For now, generate on the fly
	return generateLeafCert(domain, cm.caCert, cm.caKey)
}

func generateCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0) // 10 years validity

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CleanGate Adblock"},
			CommonName:   "CleanGate Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Write cert
	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// Write key
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, priv, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

// isCertTrusted checks if the CleanGate CA cert is in the macOS System Keychain as trusted
func isCertTrusted(certPath string) bool {
	// Use `security verify-cert` to check if the cert is trusted for SSL
	cmd := exec.Command("security", "verify-cert", "-c", certPath, "-p", "ssl")
	err := cmd.Run()
	return err == nil
}

func installToKeychain(certPath string) error {
	// Use sudo directly — it will prompt for password in the terminal
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func generateLeafCert(domain string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour * 365) // 1 year validity

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CleanGate Adblock MITM"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	return &tlsCert, err
}
