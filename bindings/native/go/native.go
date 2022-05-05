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

const SIGNATURE_SIZE = 64

func createSnapshot(snapshotPath string, password string) unsafe.Pointer {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	var ptr unsafe.Pointer = C.create(snapshotPathNative, passwordNative)

	fmt.Println("[Go] Snapshot created %x", ptr)

	return ptr
}

func loadSnapshot(snapshotPath string, password string) unsafe.Pointer {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	var ptr unsafe.Pointer = C.load(snapshotPathNative, passwordNative)

	fmt.Println("[Go] Snapshot loaded")

	return ptr
}

func destroyStronghold(stronghold_ptr unsafe.Pointer) {
	C.destroy_stronghold(stronghold_ptr)
}

func destroySignature(stronghold_ptr unsafe.Pointer) {
	C.destroy_signature(stronghold_ptr)
}

func generateKey(stronghold_ptr unsafe.Pointer, key string) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	C.generate_seed(stronghold_ptr, keyNative)
}

func sign(stronghold_ptr unsafe.Pointer, data []byte) [SIGNATURE_SIZE]byte {
	dataPtr := (*C.char)(unsafe.Pointer(&data[0]))
	dataLength := C.size_t(len(data))

	signaturePointer := C.sign(stronghold_ptr, dataPtr, dataLength)
	signatureData := *(*[]byte)(unsafe.Pointer(signaturePointer))

	var signatureDataCopy [SIGNATURE_SIZE]byte
	copy(signatureDataCopy[:], signatureData)

	fmt.Println("[Go] Signature ptr [%x]\nData: %v", signaturePointer, signatureDataCopy)

	destroySignature(signaturePointer)

	return signatureDataCopy
}
