package stronghold

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

// SetLogLevel
/**
  0 => LevelFilter::Off
  1 => LevelFilter::Error
  2 => LevelFilter::Warn
  3 => LevelFilter::Info
  4 => LevelFilter::Debug
  5 => LevelFilter::Trace
*/

func SetLogLevel(level int) {
	setLogLevel(level)
}

func (s *StrongholdNative) validate() error {
	if s.ptr == nil {
		return errors.New("snapshot is unavailable. Call Open/Create")
	}

	return nil
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

	s.ptr, err = loadSnapshot(snapshotPath, buffer.String())

	if err != nil {
		return false, err
	}

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

	s.ptr, err = createSnapshot(snapshotPath, buffer.String())

	if err != nil {
		return false, err
	}

	return true, nil
}

func (s *StrongholdNative) Close() (bool, error) {
	if err := s.validate(); err != nil {
		return false, err
	}

	destroyStronghold(s.ptr)
	s.ptr = nil

	return true, nil
}

func (s *StrongholdNative) GenerateED25519KeyPair(recordPath string) ([PublicKeySize]byte, error) {
	if err := s.validate(); err != nil {
		return [PublicKeySize]byte{}, err
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return [PublicKeySize]byte{}, err
	}

	return generateED25519KeyPair(s.ptr, buffer.String(), recordPath)
}

func (s *StrongholdNative) Sign(recordPath string, data []byte) ([SignatureSize]byte, error) {
	if err := s.validate(); err != nil {
		return [SignatureSize]byte{}, err
	}

	return sign(s.ptr, recordPath, data)
}

func (s *StrongholdNative) GetPublicKey(recordPath string) ([PublicKeySize]byte, error) {
	if err := s.validate(); err != nil {
		return [PublicKeySize]byte{}, err
	}

	return getPublicKey(s.ptr, recordPath)
}

func (s *StrongholdNative) GetPublicKeyFromDerived(index uint32) ([PublicKeySize]byte, error) {
	recordPath := fmt.Sprintf("seed%d", index)
	return getPublicKey(s.ptr, recordPath)
}

func (s *StrongholdNative) GenerateSeed() (bool, error) {
	if err := s.validate(); err != nil {
		return false, err
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return false, err
	}

	return generateSeed(s.ptr, buffer.String())
}

func (s *StrongholdNative) DeriveSeed(index uint32) (bool, error) {
	if err := s.validate(); err != nil {
		return false, err
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return false, err
	}

	return deriveSeed(s.ptr, buffer.String(), index)
}

func getHex(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, "0x")
	hex.Encode(enc[2:], b)
	return string(enc)
}

func (s *StrongholdNative) GetAddress(index uint32) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}

	publicKey, err := s.GetPublicKeyFromDerived(index)

	if err != nil {
		return "", err
	}

	addressHash := blake2b.Sum256(publicKey[:])

	return getHex(addressHash[:]), nil
}
