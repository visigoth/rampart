//go:build darwin

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// SaveCA imports the CA cert and private key into the user's login Keychain (TR20, TR23).
// The private key never touches disk — it is created in memory and imported via CGo.
// This call may prompt for Keychain authentication on macOS.
func SaveCA(certPEM, keyPEM []byte) error {
	// Parse key and build x9.63 format for SecKeyCreateWithData.
	// x9.63 P-256: 0x04 | X(32) | Y(32) | D(32) = 97 bytes.
	keyBlock, _ := decodePEM(keyPEM)
	if keyBlock == nil {
		return errors.New("invalid key PEM")
	}
	ecKey, err := x509.ParseECPrivateKey(keyBlock)
	if err != nil {
		return fmt.Errorf("parsing EC private key: %w", err)
	}
	x963 := make([]byte, 97)
	x963[0] = 0x04
	ecKey.X.FillBytes(x963[1:33])
	ecKey.Y.FillBytes(x963[33:65])
	ecKey.D.FillBytes(x963[65:97])

	// Store private key in Keychain (key never written to disk).
	if st := cgoSaveKey(x963); st != errSecSuccess() && st != errSecDuplicate() {
		return fmt.Errorf("storing key in Keychain: OSStatus %d", st)
	}

	// Store cert in Keychain.
	certDER, err := cgoCertDER(certPEM)
	if err != nil {
		return err
	}
	if st := cgoSaveCert(certDER); st != errSecSuccess() && st != errSecDuplicate() {
		_ = cgoRemoveKey()
		return fmt.Errorf("storing cert in Keychain: OSStatus %d", st)
	}

	// Set user-domain trust (may prompt for Keychain auth).
	if st := cgoSetTrust(); st != errSecSuccess() {
		_ = cgoRemoveKey()
		_ = cgoRemoveCert()
		return fmt.Errorf("setting CA trust in Keychain: OSStatus %d (user may have cancelled)", st)
	}

	return nil
}

// LoadCA retrieves the CA from the user's Keychain. The private key stays in Keychain;
// signing operations use SecKeyCreateSignature via CGo (TR29).
func LoadCA() (*CA, error) {
	certDER, err := cgoLoadCertDER()
	if err != nil {
		return nil, err
	}
	if certDER == nil {
		return nil, ErrNotInstalled
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyRef := loadKeyRefFromKeychain()
	if keyRef == 0 {
		return nil, fmt.Errorf("CA private key not found in Keychain; try 'rampart init --rotate'")
	}

	signer := &keychainSigner{
		pub:    cert.PublicKey,
		keyRef: keyRef,
	}
	setSignerFinalizer(signer)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  signer,
		Leaf:        cert,
	}
	return &CA{Cert: cert, CertPEM: certPEM, tlsCert: tlsCert}, nil
}

// IsInstalled reports whether the CA cert is present in the Keychain.
func IsInstalled() (bool, error) {
	return cgoIsInstalled(), nil
}

// RemoveCA removes the CA cert, private key, and trust settings from Keychain (TR26).
func RemoveCA() error {
	certSt := cgoRemoveCert()
	keySt := cgoRemoveKey()
	if certSt != errSecSuccess() && certSt != errSecItemNotFound() {
		return fmt.Errorf("removing CA cert from Keychain: OSStatus %d", certSt)
	}
	if keySt != errSecSuccess() && keySt != errSecItemNotFound() {
		return fmt.Errorf("removing CA key from Keychain: OSStatus %d", keySt)
	}
	return nil
}

// decodePEM decodes the first PEM block from data.
func decodePEM(data []byte) ([]byte, *pem.Block) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil
	}
	return block.Bytes, block
}
