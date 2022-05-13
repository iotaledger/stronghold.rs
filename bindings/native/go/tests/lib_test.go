// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
package tests

import (
	"fmt"
	"hash/fnv"
	"math/big"
	"math/rand"
	"os"
	"path"
	stronghold_go "stronghold"
	"testing"
)

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
	stronghold_go.SetLogLevel(5)
	stronghold := stronghold_go.NewStronghold(testPassword)
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
	success, err := stronghold.Create(dbPath)

	if err != nil {
		t.Error(err)
	}

	if !success {
		t.Error("Failed to create snapshot")
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Creation call was successful, but snapshot file is missing")
	}
}

func TestLoadingOfSnapshot(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath)
	stronghold.Close()

	stronghold, _ = initializeStrongholdTest(t, false)
	success, err := stronghold.Open(dbPath)

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
	stronghold.Create(dbPath)

	_, err := stronghold.GenerateED25519KeyPair("test")

	if err != nil {
		t.Error(err)
	}
}

func TestSign(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath)

	stronghold.GenerateED25519KeyPair("test")

	signature, err := stronghold.Sign("test", make([]byte, 32)) // Just a zeroed byte array with the length of 32

	if err != nil {
		t.Error(err)
	}

	if len(signature) != stronghold_go.SignatureSize {
		t.Error("Signature size is invalid")
	}
}

func TestGenerateSeed(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath)

	_, err := stronghold.GenerateSeed()

	if err != nil {
		t.Error(err)
	}
}

func TestGenerateSeedDerive(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath)

	stronghold.GenerateSeed()
	_, err := stronghold.DeriveSeed(1)

	if err != nil {
		t.Error(err)
	}
}

func TestGetPublicKeyFromDerivedSeed(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath)

	stronghold.GenerateSeed()
	stronghold.DeriveSeed(1)
	publicKey, err := stronghold.GetPublicKeyFromDerived(1)

	if err != nil {
		t.Error(err)
	}

	if len(publicKey) != stronghold_go.PublicKeySize {
		t.Error("Public key does not match size")
	}
}

func TestGetAddressFromDerivedSeed(t *testing.T) {
	stronghold, dbPath := initializeStrongholdTest(t, true)
	stronghold.Create(dbPath)

	stronghold.GenerateSeed()
	stronghold.DeriveSeed(1)
	address, err := stronghold.GetAddress(1)

	if err != nil {
		t.Error(err)
	}

	t.Log(address)
}

func TestErrorInvalidPath(t *testing.T) {
	stronghold := stronghold_go.NewStronghold("foobar")
	_, err := stronghold.Open("ThisPathDoesNotExist")

	if err == nil {
		t.Fail()
	}
}
