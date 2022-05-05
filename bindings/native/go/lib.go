package stronghold_go

import (
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

type StrongholdNative struct {
	ptr StrongholdPointer
}

func NewStronghold() *StrongholdNative {
	stronghold := &StrongholdNative{}

	//	runtime.SetFinalizer(stronghold, stronghold.Close)

	return stronghold
}

func (s *StrongholdNative) Open(snapshotPath string, key string) (bool, error) {
	if s.ptr != nil {
		return false, errors.New("Snapshot is already open.")
	}

	s.ptr = loadSnapshot(snapshotPath, key)

	return true, nil
}

func (s *StrongholdNative) Create(snapshotPath string, key string) (bool, error) {
	if s.ptr != nil {
		return false, errors.New("Snapshot is already open.")
	}

	s.ptr = createSnapshot(snapshotPath, key)

	return true, nil
}

func (s *StrongholdNative) Close() (bool, error) {
	if s.ptr == nil {
		return false, errors.New("No instance to be closed")
	}

	destroyStronghold(s.ptr)

	return true, nil
}

func (s *StrongholdNative) GenerateED25519KeyPair(key string, recordPath string) error {
	if s.ptr == nil {
		return errors.New("Snapshot is unavailable. Call Open/Create")
	}

	generateED25519KeyPair(s.ptr, key, recordPath)

	return nil
}

func (s *StrongholdNative) Sign(recordPath string, data []byte) ([SignatureSize]byte, error) {
	if s.ptr == nil {
		return [SignatureSize]byte{}, errors.New("Snapshot is unavailable. Call Open/Create")
	}

	signature := sign(s.ptr, recordPath, data)

	return signature, nil
}

func (s *StrongholdNative) GetPublicKey(recordPath string) ([PublicKeySize]byte, error) {
	if s.ptr == nil {
		return [PublicKeySize]byte{}, errors.New("Snapshot is unavailable. Call Open/Create")
	}

	publicKey := getPublicKey(s.ptr, recordPath)

	return publicKey, nil
}

func (s *StrongholdNative) DeriveSeed(key string, index uint32) error {
	if s.ptr == nil {
		return errors.New("Snapshot is unavailable. Call Open/Create")
	}

	deriveSeed(s.ptr, key, index)

	return nil
}

func GetHex(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, "0x")
	hex.Encode(enc[2:], b)
	return string(enc)
}

func (s *StrongholdNative) GetAddress(index uint32) (string, error) {
	if s.ptr == nil {
		return "", errors.New("Snapshot is unavailable. Call Open/Create")
	}

	recordPath := fmt.Sprintf("seed%d", index)
	publicKey := getPublicKey(s.ptr, recordPath)

	addressHash := blake2b.Sum256(publicKey[:])

	return GetHex(addressHash[:]), nil
}
