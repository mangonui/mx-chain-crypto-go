package x25519

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// EncryptionNonceSize represents the length of the nonce used in the encryption process
const EncryptionNonceSize = 24
const EncryptionVersion = 1
const EncryptionCipher = "x25519-xsalsa20-poly1305"

// EncryptedDataIdentities holds the data associated with the identities involved
// in the encryption process - who is able to decrypt, the ephemeral public key
// used to encrypt, and the address of the originator of the encryption
// used to authenticate that indeed a message was encrypted by Bob
// for Alice (remember that the private key used for encryption
// is ephemeral - in order to avoid nonce reuses and
// multipurpose use of the same secret)
type EncryptedDataIdentities struct {
	Recipient        string `json:"recipient"`
	EphemeralPubKey  string `json:"ephemeralPubKey"`
	OriginatorPubKey string `json:"originatorPubKey"`
}

// EncryptedCryptoData holds crypto information such as the cipher used, the ciphertext itself
// and the authentication code
type EncryptedCryptoData struct {
	Cipher     string `json:"cipher"`
	Ciphertext string `json:"ciphertext"`
	MAC        string `json:"mac"`
}

// EncryptedData holds the needed information of an encrypted
// message required to correctly be decrypted by the recipient
type EncryptedData struct {
	Nonce      string                  `json:"nonce"`
	Version    uint8                   `json:"version"`
	Crypto     EncryptedCryptoData     `json:"crypto"`
	Identities EncryptedDataIdentities `json:"identities"`
}

// Encrypt generates a public key encryption for a message using a recipient edwards public key and an ephemeral
// private key generated on the spot. The senderPrivateKey param is used to authenticate the encryption
// that normally should happen between two edwards curve identities.
func (ed *EncryptedData) Encrypt(data []byte, recipientPubKey crypto.PublicKey, senderPrivateKey crypto.PrivateKey) error {
	suite := ed25519.NewEd25519()
	ephemeralEdScalar, ephemeralEdPoint := suite.CreateKeyPair()

	recipientPubKeyBytes, err := recipientPubKey.ToByteArray()
	if err != nil {
		return err
	}

	nonce, err := ed.generateEncryptionNonce(data)
	if err != nil {
		return err
	}

	ciphertext, err := ed.createCiphertext(data, ephemeralEdScalar, recipientPubKey, nonce)
	if err != nil {
		return err
	}

	ephemeralEdPointBytes, err := ephemeralEdPoint.MarshalBinary()
	if err != nil {
		return err
	}
	mac, err := ed.generateMAC(senderPrivateKey, append(ciphertext, ephemeralEdPointBytes...))
	if err != nil {
		return err
	}

	senderPubKey, err := generatePublicBytes(senderPrivateKey)
	if err != nil {
		return err
	}

	ed.Nonce = hex.EncodeToString(nonce)
	ed.Version = EncryptionVersion
	ed.Crypto.Cipher = EncryptionCipher
	ed.Crypto.Ciphertext = hex.EncodeToString(ciphertext)
	ed.Crypto.MAC = hex.EncodeToString(mac)
	ed.Identities.EphemeralPubKey = hex.EncodeToString(ephemeralEdPointBytes)
	ed.Identities.OriginatorPubKey = hex.EncodeToString(senderPubKey)
	ed.Identities.Recipient = hex.EncodeToString(recipientPubKeyBytes)

	return nil
}

func generatePublicBytes(privateKey crypto.PrivateKey) ([]byte, error) {
	if checkedPrivateKey, ok := privateKey.(crypto.CheckedPrivateKey); ok {
		publicKey, err := checkedPrivateKey.GeneratePublicChecked()
		if err != nil {
			return nil, err
		}

		return publicKey.ToByteArray()
	}

	return privateKey.GeneratePublic().ToByteArray()
}

// Decrypt returns the plain text associated to a ciphertext that was previously encrypted
// using the public key of the recipient
func (ed *EncryptedData) Decrypt(recipientPrivateKey crypto.PrivateKey) ([]byte, error) {
	encryptedMessage, err := hex.DecodeString(ed.Crypto.Ciphertext)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := hex.DecodeString(ed.Identities.EphemeralPubKey)
	if err != nil {
		return nil, err
	}

	err = ed.verifyAuthMessage(append(encryptedMessage, pubKeyBytes...))
	if err != nil {
		return nil, err
	}

	return ed.decrypt(recipientPrivateKey, pubKeyBytes, encryptedMessage)
}

func (ed *EncryptedData) decrypt(recipientPrivateKey crypto.PrivateKey, encryptPubKey []byte, encryptedMessage []byte) ([]byte, error) {
	var nonce24 [24]byte
	var pubKey32 [32]byte
	var secretKey32 [32]byte

	nonce, err := hex.DecodeString(ed.Nonce)
	if err != nil {
		return nil, err
	}
	copy(nonce24[:], nonce)

	var recipientX25519 x25519Point
	err = recipientX25519.FromEd25519(encryptPubKey)
	if err != nil {
		return nil, err
	}

	x25519Bytes, err := recipientX25519.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(pubKey32[:], x25519Bytes)
	secretKeyBytes, err := recipientPrivateKey.ToByteArray()
	if err != nil {
		return nil, err
	}

	h := sha512.New()
	h.Write(secretKeyBytes[:curve25519.ScalarSize])
	secretKeyBytes32 := h.Sum(nil)
	copy(secretKey32[:], secretKeyBytes32)

	decryptedMessage, success := box.Open([]byte{}, encryptedMessage, &nonce24, &pubKey32, &secretKey32)
	if !success {
		return nil, crypto.ErrFailedAuthentication
	}

	return decryptedMessage, nil
}

func (ed *EncryptedData) edScalarToX25519(scalar crypto.Scalar) (*x25519Scalar, error) {
	ephemeralScalarBytes, err := scalar.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var ephemeralXScalar x25519Scalar
	err = ephemeralXScalar.FromX25519(ephemeralScalarBytes)
	if err != nil {
		return nil, err
	}

	return &ephemeralXScalar, nil
}

func (ed *EncryptedData) generateEncryptionNonce(data []byte) ([]byte, error) {
	deterministicNonce := sha256.New()
	_, err := deterministicNonce.Write(data)
	if err != nil {
		return nil, err
	}

	randomness := cryptorand.Reader
	randomNonce := make([]byte, EncryptionNonceSize/2)
	if _, err = randomness.Read(randomNonce); err != nil {
		return nil, err
	}

	nonce := append(deterministicNonce.Sum([]byte{})[:EncryptionNonceSize/2], randomNonce...)

	return nonce, nil
}

func (ed *EncryptedData) generateMAC(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	authMessage := sha256.New()
	_, err := authMessage.Write(data)
	if err != nil {
		return nil, err
	}

	signer := singlesig.Ed25519Signer{}
	sig, err := signer.Sign(privateKey, authMessage.Sum([]byte{}))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (ed *EncryptedData) createCiphertext(data []byte, edPrivateKey crypto.Scalar, recipientPubKey crypto.PublicKey, nonce []byte) ([]byte, error) {
	privateKey, err := ed.edScalarToX25519(edPrivateKey)
	if err != nil {
		return nil, err
	}

	recipientPubKeyBytes, err := recipientPubKey.ToByteArray()
	if err != nil {
		return nil, err
	}

	var recipientX25519PubKey x25519Point
	err = recipientX25519PubKey.FromEd25519(recipientPubKeyBytes)
	if err != nil {
		return nil, err
	}

	var nonce24 [24]byte
	var recipientPubKey32 [32]byte
	var ephemeralScalar32 [32]byte
	copy(nonce24[:], nonce)
	copy(recipientPubKey32[:], recipientX25519PubKey.PublicKey)
	copy(ephemeralScalar32[:], privateKey.PrivateKey)

	return box.Seal([]byte{}, data, &nonce24, &recipientPubKey32, &ephemeralScalar32), nil
}

func (ed *EncryptedData) verifyAuthMessage(msg []byte) error {
	originatorPubKeyBytes, err := hex.DecodeString(ed.Identities.OriginatorPubKey)
	if err != nil {
		return err
	}
	macBytes, err := hex.DecodeString(ed.Crypto.MAC)
	if err != nil {
		return err
	}

	authMessage := sha256.New()
	_, err = authMessage.Write(msg)
	if err != nil {
		return err
	}

	suite := ed25519.NewEd25519()
	keygen := signing.NewKeyGenerator(suite)
	originatorPubKey, err := keygen.PublicKeyFromByteArray(originatorPubKeyBytes)
	if err != nil {
		return err
	}

	signer := singlesig.Ed25519Signer{}
	err = signer.Verify(originatorPubKey, authMessage.Sum(nil), macBytes)
	if err != nil {
		return err
	}

	return nil
}
