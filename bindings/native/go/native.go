package stronghold_go

import (
	"fmt"
	"unsafe"
)

/*
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../../target/debug/ -L${SRCDIR}/../../../target/debug/ -lstronghold_native
#include "./../native.h"
*/
import "C"

type StrongholdPointer *C.struct_StrongholdWrapper

const SignatureSize = 64
const PublicKeySize = 32

func createSnapshot(snapshotPath string, key string) StrongholdPointer {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	ptr := C.create(snapshotPathNative, keyNative)

	fmt.Printf("[Go] Snapshot created %x\n", ptr)

	return ptr
}

func loadSnapshot(snapshotPath string, key string) StrongholdPointer {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	ptr := C.load(snapshotPathNative, keyNative)

	fmt.Println("[Go] Snapshot loaded")

	return ptr
}

func destroyStronghold(strongholdPtr StrongholdPointer) {
	C.destroy_stronghold(strongholdPtr)
}

func destroyDataPointer(strongholdPtr *C.uchar) {
	C.destroy_data_pointer(strongholdPtr)
}

func generateED25519KeyPair(strongholdPtr StrongholdPointer, key string, recordPath string) [PublicKeySize]byte {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	chainCodePointer := C.generate_ed25519_keypair(strongholdPtr, keyNative, recordPathNative)
	chainCodeData := *(*[]byte)(unsafe.Pointer(chainCodePointer))

	var chainCodeDataCopy [PublicKeySize]byte
	copy(chainCodeDataCopy[:], chainCodeData)

	destroyDataPointer(chainCodePointer)

	return chainCodeDataCopy
}

func sign(strongholdPtr StrongholdPointer, recordPath string, data []byte) [SignatureSize]byte {
	dataPtr := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLength := C.size_t(len(data))

	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	signaturePointer := C.sign(strongholdPtr, recordPathNative, dataPtr, dataLength)
	signatureData := *(*[]byte)(unsafe.Pointer(signaturePointer))

	var signatureDataCopy [SignatureSize]byte
	copy(signatureDataCopy[:], signatureData)

	fmt.Printf("[Go] Signature ptr [%x]\nData: %v\n", signaturePointer, signatureDataCopy)

	destroyDataPointer(signaturePointer)

	return signatureDataCopy
}

func getPublicKey(strongholdPtr StrongholdPointer, recordPath string) [PublicKeySize]byte {
	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	publicKeyPointer := C.get_public_key(strongholdPtr, recordPathNative)
	publicKeyData := *(*[]byte)(unsafe.Pointer(publicKeyPointer))

	var publicKeyDataCopy [PublicKeySize]byte
	copy(publicKeyDataCopy[:], publicKeyData)

	fmt.Printf("[Go] Signature ptr [%x]\nData: %v\n", publicKeyPointer, publicKeyDataCopy)

	destroyDataPointer(publicKeyPointer)

	return publicKeyDataCopy
}

func generateSeed(strongholdPtr StrongholdPointer, key string) bool {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	return bool(C.generate_seed(strongholdPtr, keyNative))
}

func deriveSeed(strongholdPtr StrongholdPointer, key string, index uint32) bool {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	indexNative := C.uint(index)

	return bool(C.derive_seed(strongholdPtr, keyNative, indexNative))
}
