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

const SIGNATURE_SIZE = 64

func createSnapshot(snapshotPath string, password string) *C.struct_StrongholdWrapper {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	ptr := C.create(snapshotPathNative, passwordNative)

	fmt.Printf("[Go] Snapshot created %x\n", ptr)

	return ptr
}

func loadSnapshot(snapshotPath string, password string) *C.struct_StrongholdWrapper {
	snapshotPathNative := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(snapshotPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	ptr := C.load(snapshotPathNative, passwordNative)

	fmt.Println("[Go] Snapshot loaded")

	return ptr
}

func destroyStronghold(stronghold_ptr *C.struct_StrongholdWrapper) {
	C.destroy_stronghold(stronghold_ptr)
}

func destroySignature(stronghold_ptr *C.uchar) {
	C.destroy_signature(stronghold_ptr)
}

func generateKey(stronghold_ptr *C.struct_StrongholdWrapper, key string) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	C.generate_seed(stronghold_ptr, keyNative)
}

func sign(stronghold_ptr *C.struct_StrongholdWrapper, data []byte) [SIGNATURE_SIZE]byte {
	dataPtr := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLength := C.size_t(len(data))

	signaturePointer := C.sign(stronghold_ptr, dataPtr, dataLength)
	signatureData := *(*[]byte)(unsafe.Pointer(signaturePointer))

	var signatureDataCopy [SIGNATURE_SIZE]byte
	copy(signatureDataCopy[:], signatureData)

	fmt.Printf("[Go] Signature ptr [%x]\nData: %v\n", signaturePointer, signatureDataCopy)

	destroySignature(signaturePointer)

	return signatureDataCopy
}
