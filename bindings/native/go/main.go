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

	fmt.Println("Snapshot created %x", ptr)

	return ptr
}

func LoadSnapshot(vaultPath string, password string) unsafe.Pointer {
	vaultPathNative := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(vaultPathNative))

	passwordNative := C.CString(password)
	defer C.free(unsafe.Pointer(passwordNative))

	var ptr unsafe.Pointer = C.load(vaultPathNative, passwordNative)

	fmt.Println("Snapshot loaded")

	return ptr
}

func DestroyInstance(stronghold_ptr unsafe.Pointer) {
	C.destroy(stronghold_ptr)
}

func GenerateKey(stronghold_ptr unsafe.Pointer, key string) {
	keyNative := C.CString(key)
	defer C.free(unsafe.Pointer(keyNative))

	C.generate_seed(stronghold_ptr, keyNative)
}

func main() {
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}

	CreateSnapshot(path+"/test.db", "qawsedrf")
}
