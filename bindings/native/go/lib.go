package stronghold_go

import (
	"errors"
)

type StrongholdNative struct {
	ptr StrongholdPointer
}

func NewStronghold() *StrongholdNative {
	stronghold := &StrongholdNative{}

	//	runtime.SetFinalizer(stronghold, stronghold.Close)

	return stronghold
}

func (s *StrongholdNative) Open(snapshotPath string, password string) (bool, error) {
	if s.ptr != nil {
		return false, errors.New("Snapshot is already open.")
	}

	s.ptr = loadSnapshot(snapshotPath, password)

	return true, nil
}

func (s *StrongholdNative) Create(snapshotPath string, password string) (bool, error) {
	if s.ptr != nil {
		return false, errors.New("Snapshot is already open.")
	}

	s.ptr = createSnapshot(snapshotPath, password)

	return true, nil
}

func (s *StrongholdNative) Close() (bool, error) {
	if s.ptr == nil {
		return false, errors.New("No instance to be closed")
	}

	destroyStronghold(s.ptr)

	return true, nil
}

func (s *StrongholdNative) GenerateKey(password string) (bool, error) {
	if s.ptr == nil {
		return false, errors.New("Snapshot is unavailable. Call Open/Create")
	}

	generateKey(s.ptr, password)

	return true, nil
}

func (s *StrongholdNative) Sign(data []byte) ([SIGNATURE_SIZE]byte, error) {
	if s.ptr == nil {
		return [SIGNATURE_SIZE]byte{}, errors.New("Snapshot is unavailable. Call Open/Create")
	}

	signature := sign(s.ptr, data)

	return signature, nil
}
