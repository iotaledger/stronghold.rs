package tests

import (
	"fmt"
	"hash/fnv"
	"math/big"
	"math/rand"
	"os"
	"path"
	"stronghold_go"
	"testing"
)

const snapshotFileName = "test.db"
const testPassword = "qawsedrf"

func randomFileName() string {
	big := new(big.Int)
	big.SetInt64(int64(rand.Uint64()))

	hash := fnv.New32a()
	hash.Write(big.Bytes())

	return fmt.Sprint(hash.Sum32())
}

func getNewDBPath() string {
	cwd, _ := os.Getwd()

	return path.Join(cwd, fmt.Sprintf("%v.db", randomFileName()))
}

func initializeStrongholdTest(t *testing.T, withNewPath bool) (*stronghold_go.StrongholdNative, string) {
	stronghold := stronghold_go.NewStronghold()

	if withNewPath {
		dbPath := getNewDBPath()

		t.Cleanup(func() {
			os.Remove(dbPath)
		})

		return stronghold, dbPath
	}

	return stronghold, ""
}

func TestCreationOfSnapshot(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	success, err := stronghold.Create(dbPath, testPassword)

	if err != nil {
		t.Error(err)
	}

	if !success {
		t.Error("Failed to create snapshot")
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Creation call was successful, but snapsot file is missing")
	}
}

func TestLoadingOfSnapshot(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath, testPassword)
	stronghold.Close()

	stronghold, _ = initializeStrongholdTest(t, false)
	success, err := stronghold.Open(dbPath, testPassword)

	if err != nil {
		t.Error(err)
	}

	if !success {
		t.Error("Failed to open snapshot")
	}
}

/**
* As Stronghold does not leak the private key, it's impossible to know if we actually generate a valid one
* and if we get a valid signature from Sign back.
 */

func TestKeyGeneration(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath, testPassword)

	err := stronghold.GenerateED25519KeyPair(testPassword, "test")

	if err != nil {
		t.Error(err)
	}
}

func TestSign(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath, testPassword)

	stronghold.GenerateED25519KeyPair(testPassword, "test")

	signature, err := stronghold.Sign("test", make([]byte, 32)) // Just a zeroed byte array with the length of 32

	if err != nil {
		t.Error(err)
	}

	if len(signature) != 64 {
		t.Error("Signature size is invalid")
	}
}
