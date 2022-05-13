package stronghold

import (
	"errors"
	"strings"
	"unsafe"
)

// TODO: Clean up paths once we have a working build pipeline
/*
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../../target/debug/ -L${SRCDIR}/../../../target/debug/ -L${SRCDIR}/dist/ -L${SRCDIR}/../dist/ -lstronghold_native
#include "dist/stronghold_native.h"
*/
import "C"

type StrongholdPointer *C.struct_StrongholdWrapper

const SignatureSize = 64
const PublicKeySize = 32

func createSnapshot(snapshotPath string, key string) (StrongholdPointer, error) {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	ptr := unsafe.Pointer(C.stronghold_create(snapshotPathNative, keyNative))

	if err := handlePtrError(ptr != nil); err != nil {
		return nil, err
	}

	return StrongholdPointer(ptr), nil
}

func loadSnapshot(snapshotPath string, key string) (StrongholdPointer, error) {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	ptr := unsafe.Pointer(C.stronghold_load(snapshotPathNative, keyNative))

	if err := handlePtrError(ptr != nil); err != nil {
		return nil, err
	}

	return StrongholdPointer(ptr), nil
}

func destroyStronghold(strongholdPtr StrongholdPointer) {
	C.stronghold_destroy_stronghold(strongholdPtr)
}

func destroyErrorPointer(ptr *C.char) {
	C.stronghold_destroy_error(ptr)
}

func destroyDataPointer(ptr unsafe.Pointer) {
	C.stronghold_destroy_data_pointer((*C.uchar)(ptr)) //nolint:typecheck
}

func generateED25519KeyPair(strongholdPtr StrongholdPointer, key string, recordPath string) ([PublicKeySize]byte, error) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	chainCodePointer := unsafe.Pointer(C.stronghold_generate_ed25519_keypair(strongholdPtr, keyNative, recordPathNative))

	if err := handlePtrError(chainCodePointer != nil); err != nil {
		return [PublicKeySize]byte{}, err
	}

	chainCodeData := *(*[]byte)(chainCodePointer)

	var chainCodeDataCopy [PublicKeySize]byte
	copy(chainCodeDataCopy[:], chainCodeData)

	destroyDataPointer(chainCodePointer)

	return chainCodeDataCopy, nil
}

func sign(strongholdPtr StrongholdPointer, recordPath string, data []byte) ([SignatureSize]byte, error) {
	dataPtr := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLength := C.size_t(len(data))

	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	signaturePointer := unsafe.Pointer(C.stronghold_sign(strongholdPtr, recordPathNative, dataPtr, dataLength))

	if err := handlePtrError(signaturePointer != nil); err != nil {
		return [SignatureSize]byte{}, err
	}

	signatureData := *(*[]byte)(signaturePointer)

	var signatureDataCopy [SignatureSize]byte
	copy(signatureDataCopy[:], signatureData)

	destroyDataPointer(signaturePointer)

	return signatureDataCopy, nil
}

func getPublicKey(strongholdPtr StrongholdPointer, recordPath string) ([PublicKeySize]byte, error) {
	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	publicKeyPointer := unsafe.Pointer(C.stronghold_get_public_key(strongholdPtr, recordPathNative))

	if err := handlePtrError(publicKeyPointer != nil); err != nil {
		return [PublicKeySize]byte{}, err
	}

	publicKeyData := *(*[]byte)(publicKeyPointer)

	var publicKeyDataCopy [PublicKeySize]byte
	copy(publicKeyDataCopy[:], publicKeyData)

	destroyDataPointer(publicKeyPointer)

	return publicKeyDataCopy, nil
}

func generateSeed(strongholdPtr StrongholdPointer, key string) (bool, error) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	seedGenerated := bool(C.stronghold_generate_seed(strongholdPtr, keyNative))

	if err := handlePtrError(seedGenerated); err != nil {
		return false, err
	}

	return true, nil
}

func deriveSeed(strongholdPtr StrongholdPointer, key string, index uint32) (bool, error) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	indexNative := C.uint(index)
	seedDerived := bool(C.stronghold_derive_seed(strongholdPtr, keyNative, indexNative))

	if err := handlePtrError(seedDerived); err != nil {
		return false, err
	}

	return true, nil
}

func handlePtrError(isValidResult bool) error {
	if isValidResult {
		return nil
	}

	err := getLastError()

	if err == nil {
		return errors.New("failed to fetch requested data with an unknown error")
	}

	return err
}

func getLastError() error {
	errorPtr := C.stronghold_get_last_error()

	if errorPtr == nil {
		return nil
	}

	errorData := C.GoString(errorPtr)
	errorStringCopy := strings.Clone(string(errorData))

	destroyErrorPointer(errorPtr)

	return errors.New(errorStringCopy)
}

func setLogLevel(level int) {
	C.stronghold_set_log_level(C.size_t(level))
}
