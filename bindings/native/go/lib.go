package stronghold_go

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"
)

type StrongholdNative struct {
	ptr     StrongholdPointer
	enclave *memguard.Enclave
}

func NewStronghold(key string) *StrongholdNative {
	stronghold := &StrongholdNative{}
	stronghold.enclave = memguard.NewEnclave([]byte(key))
	return stronghold
}

func (s *StrongholdNative) Open(snapshotPath string) (bool, error) {
	if s.ptr != nil {
		return false, errors.New("snapshot is already open")
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return false, err
	}

	s.ptr = loadSnapshot(snapshotPath, buffer.String())

	return true, nil
}

func (s *StrongholdNative) Create(snapshotPath string) (bool, error) {
	if s.ptr != nil {
		return false, errors.New("snapshot is already open")
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return false, err
	}

	s.ptr = createSnapshot(snapshotPath, buffer.String())

	return true, nil
}

func (s *StrongholdNative) Close() (bool, error) {
	if s.ptr == nil {
		return false, errors.New("no instance to be closed")
	}

	destroyStronghold(s.ptr)

	return true, nil
}

func (s *StrongholdNative) GenerateED25519KeyPair(recordPath string) error {
	if s.ptr == nil {
		return errors.New("snapshot is unavailable. Call Open/Create")
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return err
	}

	generateED25519KeyPair(s.ptr, buffer.String(), recordPath)

	return nil
}

func (s *StrongholdNative) Sign(recordPath string, data []byte) ([SignatureSize]byte, error) {
	if s.ptr == nil {
		return [SignatureSize]byte{}, errors.New("snapshot is unavailable. Call Open/Create")
	}

	signature := sign(s.ptr, recordPath, data)

	return signature, nil
}

func (s *StrongholdNative) GetPublicKey(recordPath string) ([PublicKeySize]byte, error) {
	if s.ptr == nil {
		return [PublicKeySize]byte{}, errors.New("snapshot is unavailable. Call Open/Create")
	}

	publicKey := getPublicKey(s.ptr, recordPath)

	return publicKey, nil
}

func (s *StrongholdNative) GetPublicKeyFromDerived(index uint32) [PublicKeySize]byte {
	recordPath := fmt.Sprintf("seed%d", index)
	publicKey := getPublicKey(s.ptr, recordPath)
	return publicKey
}

func (s *StrongholdNative) GenerateSeed() error {
	if s.ptr == nil {
		return errors.New("snapshot is unavailable. Call Open/Create")
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return err
	}

	generateSeed(s.ptr, buffer.String())

	return nil
}

func (s *StrongholdNative) DeriveSeed(index uint32) error {
	if s.ptr == nil {
		return errors.New("snapshot is unavailable. Call Open/Create")
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return err
	}

	deriveSeed(s.ptr, buffer.String(), index)

	return nil
}

func getHex(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, "0x")
	hex.Encode(enc[2:], b)
	return string(enc)
}

func (s *StrongholdNative) GetAddress(index uint32) (string, error) {
	if s.ptr == nil {
		return "", errors.New("snapshot is unavailable. Call Open/Create")
	}

	publicKey := s.GetPublicKeyFromDerived(index)

	addressHash := blake2b.Sum256(publicKey[:])

	fmt.Println(publicKey)
	fmt.Println(addressHash)
	fmt.Printf("len: %v\n", len(addressHash))
	fmt.Println(getHex(addressHash[:]))
	return getHex(addressHash[:]), nil
}
