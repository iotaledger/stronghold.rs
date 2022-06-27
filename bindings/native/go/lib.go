// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
package stronghold

import (
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"
	"os"
)

type StrongholdNative struct {
	ptr     StrongholdPointer
	enclave *memguard.Enclave
}

func zeroKeyBuffer(data *[]byte) {
	for i := 0; i < len(*data); i++ {
		(*data)[i] = 0
	}
}

// NewStronghold will safely clear the provided key and make it unusable after this call.
func NewStronghold(key []byte) *StrongholdNative {
	stronghold := NewStrongholdUnsafe(key)
	zeroKeyBuffer(&key)
	return stronghold
}

// NewStrongholdUnsafe creates a Stronghold instance without clearing the provided key.
// This might leave the provided key inside readable memory space.
func NewStrongholdUnsafe(key []byte) *StrongholdNative {
	stronghold := &StrongholdNative{}
	stronghold.enclave = memguard.NewEnclave(key)
	return stronghold
}

func NewStrongholdWithEnclave(enclave *memguard.Enclave) *StrongholdNative {
	stronghold := &StrongholdNative{}
	stronghold.enclave = enclave
	return stronghold
}

type LogLevel int

const (
	LogLevelOff LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

func SetLogLevel(level LogLevel) {
	setLogLevel(int(level))
}

func (s *StrongholdNative) validate(customErrorMessage string) error {
	if s.ptr == nil {
		return errors.New(customErrorMessage)
	}

	return nil
}

func (s *StrongholdNative) OpenOrCreate(snapshotPath string) (bool, error) {
	if _, err := os.Stat(snapshotPath); errors.Is(err, os.ErrNotExist) {
		return s.Create(snapshotPath)
	}

	return s.Open(snapshotPath)
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
	if err := s.validate("instance is already closed"); err != nil {
		return false, err
	}

	destroyStronghold(s.ptr)
	s.ptr = nil

	return true, nil
}

func (s *StrongholdNative) GenerateED25519KeyPair(recordPath string) ([PublicKeySize]byte, error) {
	if err := s.validate("stronghold is closed. Call open()"); err != nil {
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
	if err := s.validate("stronghold is closed. Call open()"); err != nil {
		return [SignatureSize]byte{}, err
	}

	return sign(s.ptr, recordPath, data)
}

func (s* StrongholdNative) SignForDerived(index uint32, data []byte) ([SignatureSize]byte, error) {
	recordPath := fmt.Sprintf("seed.%d", index)
	return s.Sign(recordPath, data)
}

func (s *StrongholdNative) GetPublicKey(recordPath string) ([PublicKeySize]byte, error) {
	if err := s.validate("stronghold is closed. Call open()"); err != nil {
		return [PublicKeySize]byte{}, err
	}

	return getPublicKey(s.ptr, recordPath)
}

func (s *StrongholdNative) GetPublicKeyFromDerived(index uint32) ([PublicKeySize]byte, error) {
	recordPath := fmt.Sprintf("seed.%d", index)
	return getPublicKey(s.ptr, recordPath)
}

func (s *StrongholdNative) GenerateSeed() (bool, error) {
	if err := s.validate("stronghold is closed. Call open()"); err != nil {
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
	if err := s.validate("stronghold is closed. Call open()"); err != nil {
		return false, err
	}

	buffer, err := s.enclave.Open()
	defer buffer.Destroy()

	if err != nil {
		return false, err
	}

	return deriveSeed(s.ptr, buffer.String(), index)
}

func (s *StrongholdNative) GetAddress(index uint32) ([PublicKeySize]byte, error) {
	if err := s.validate("stronghold is closed. Call open()"); err != nil {
		return [PublicKeySize]byte{}, err
	}

	publicKey, err := s.GetPublicKeyFromDerived(index)

	if err != nil {
		return [PublicKeySize]byte{}, err
	}

	addressHash := blake2b.Sum256(publicKey[:])

	return addressHash, nil
}
