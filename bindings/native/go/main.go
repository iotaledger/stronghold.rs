package main

/*
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../../target/debug/ -L${SRCDIR}/../../../target/debug/ -lstronghold_native
#include "./../native.h"
*/
import "C"
import (
	"fmt"
	"log"
	"os"
	"unsafe"
)

func CreateSnapshot(vaultPath string, password string) unsafe.Pointer {
	vaultPathNative := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(vaultPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	var ptr unsafe.Pointer = C.create(vaultPathNative, passwordNative)

	fmt.Println("[Go] Snapshot created %x", ptr)

	return ptr
}

func LoadSnapshot(vaultPath string, password string) unsafe.Pointer {
	vaultPathNative := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(vaultPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	var ptr unsafe.Pointer = C.load(vaultPathNative, passwordNative)

	fmt.Println("[Go] Snapshot loaded")

	return ptr
}

func DestroyStronghold(stronghold_ptr unsafe.Pointer) {
	C.destroy_stronghold(stronghold_ptr)
}

func DestroySignature(stronghold_ptr unsafe.Pointer) {
	C.destroy_signature(stronghold_ptr)
}

func GenerateKey(stronghold_ptr unsafe.Pointer, key string) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	C.generate_seed(stronghold_ptr, keyNative)
}

func Sign(stronghold_ptr unsafe.Pointer, data []byte) []byte {
	dataPtr := (*C.char)(unsafe.Pointer(&data[0]))
	dataLength := C.size_t(len(data))

	signaturePointer := C.sign(stronghold_ptr, dataPtr, dataLength)
	signatureData := *(*[]byte)(unsafe.Pointer(signaturePointer))
	signatureDataCopy := make([]byte, 64)

	copy(signatureDataCopy, signatureData)

	fmt.Println("[Go] Signature ptr [%x]\nData: %v", signaturePointer, signatureDataCopy)

	DestroySignature(signaturePointer)

	return signatureDataCopy
}

func main() {
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}

	stronghold := CreateSnapshot(path+"/test.db", "qawsedrf")
	GenerateKey(stronghold, "qawsedrf")
	Sign(stronghold, make([]byte, 32)) // Just a zeroed data input with the length of 32
}
