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

func generateED25519KeyPair(strongholdPtr StrongholdPointer, key string, recordPath string) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	C.generate_ed25519_keypair(strongholdPtr, keyNative, recordPathNative)
}

func sign(stronghold_ptr StrongholdPointer, recordPath string, data []byte) [SignatureSize]byte {
	dataPtr := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLength := C.size_t(len(data))

	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	signaturePointer := C.sign(stronghold_ptr, recordPathNative, dataPtr, dataLength)
	signatureData := *(*[]byte)(unsafe.Pointer(signaturePointer))

	var signatureDataCopy [SignatureSize]byte
	copy(signatureDataCopy[:], signatureData)

	fmt.Printf("[Go] Signature ptr [%x]\nData: %v\n", signaturePointer, signatureDataCopy)

	destroyDataPointer(signaturePointer)

	return signatureDataCopy
}

func getPublicKey(stronghold_ptr StrongholdPointer, recordPath string) [PublicKeySize]byte {
	recordPathNative := C.CString(recordPath)
	defer C.free(unsafe.Pointer(recordPathNative))

	publicKeyPointer := C.get_public_key(stronghold_ptr, recordPathNative)
	publicKeyData := *(*[]byte)(unsafe.Pointer(publicKeyPointer))

	var publicKeyDataCopy [PublicKeySize]byte
	copy(publicKeyDataCopy[:], publicKeyData)

	fmt.Printf("[Go] Signature ptr [%x]\nData: %v\n", publicKeyPointer, publicKeyDataCopy)

	destroyDataPointer(publicKeyPointer)

	return publicKeyDataCopy
}

func generateSeed(stronghold_ptr StrongholdPointer, key string) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	C.generate_seed(stronghold_ptr, keyNative)
}

func deriveSeed(stronghold_ptr StrongholdPointer, key string, index uint32) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	indexNative := C.uint(index)

	C.derive_seed(stronghold_ptr, keyNative, indexNative)
}
