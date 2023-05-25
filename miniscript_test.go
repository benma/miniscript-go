package miniscript

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitString(t *testing.T) {
	separators := func(c rune) bool {
		return c == '(' || c == ')' || c == ','
	}

	require.Equal(t, []string{}, splitString("", separators))
	require.Equal(t, []string{"0"}, splitString("0", separators))
	require.Equal(t, []string{"0", ")", "(", "1", "("}, splitString("0)(1(", separators))
	require.Equal(t,
		[]string{"or_b", "(", "pk", "(", "key_1", ")", ",", "s:pk", "(", "key_2", ")", ")"},
		splitString("or_b(pk(key_1),s:pk(key_2))", separators))
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test vectors for miniscripts that are invalid (failed type check).
func TestInvalid(t *testing.T) {
	file, err := os.Open("testdata/invalid_from_alloy.txt")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		i++
		_, err := Parse(line)
		assert.Error(t, err, "failure on line %d: %s", i, line)
	}

	require.NoError(t, scanner.Err())
}

func checkMiniscript(miniscript string, expectedType string) error {
	node, err := Parse(miniscript)
	if err != nil {
		return err
	}
	if err := node.IsValidTopLevel(); err != nil {
		return err
	}
	sortString := func(s string) string {
		r := []rune(s)
		sort.Slice(r, func(i, j int) bool {
			return r[i] < r[j]
		})
		return string(r)
	}
	if sortString(expectedType) != sortString(node.typeRepr()) {
		return fmt.Errorf("Expected type %s, got %s", sortString(expectedType), sortString(node.typeRepr()))
	}
	return nil
}

// Test vectors for valid miniscript expressions including the expecte type.
func TestValid8f1e8FromAlloy(t *testing.T) {
	file, err := os.Open("testdata/valid_8f1e8_from_alloy.txt")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		miniscript, expectedType, found := strings.Cut(line, " ")
		require.True(t, found, "malformed test on line %d: %s", i, line)
		i++
		assert.NoError(t,
			checkMiniscript(miniscript, expectedType),
			"failure on line %d: %s", i, line)
	}

	require.NoError(t, scanner.Err())
}

// Test vectors for valid miniscript expressions including the expecte type.
func TestValidFromAlloy(t *testing.T) {
	file, err := os.Open("testdata/valid_from_alloy.txt")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		miniscript, expectedType, found := strings.Cut(line, " ")
		require.True(t, found, "malformed test on line %d: %s", i, line)
		i++
		assert.NoError(t,
			checkMiniscript(miniscript, expectedType),
			"failure on line %d: %s", i, line)
	}

	require.NoError(t, scanner.Err())
}

// Test vectors for miniscript expressions that are valid but do not contain the `m` type property,
// i.e. the script is guaranteed to have a non-malleable satisfaction.
func TestMalleableFromAlloy(t *testing.T) {
	file, err := os.Open("testdata/malleable_from_alloy.txt")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		miniscript, expectedType, found := strings.Cut(line, " ")
		assert.True(t, found, "malformed test on line %d: %s", i, line)
		i++
		assert.NoError(t,
			checkMiniscript(miniscript, expectedType),
			"failure on line %d: %s", i, line)
	}

	require.NoError(t, scanner.Err())
}

// Test that the scriptlen computation is accurate by comparing it to the size of the actually
// generated script.
func TestScriptLen(t *testing.T) {
	file, err := os.Open("testdata/valid_from_alloy.txt")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		miniscript, _, found := strings.Cut(line, " ")
		require.True(t, found, "malformed test on line %d: %s", i, line)
		i++
		node, err := Parse(miniscript)
		require.NoError(t, err)
		require.NoError(t, node.ApplyVars(func(identifier string) ([]byte, error) {
			if len(identifier) == 64 {
				return nil, nil
			}
			// Return an arbitary unique 33 bytes
			return append(chainhash.HashB([]byte(identifier)), 0), nil
		}))
		script, err := node.Script()
		require.NoError(t, err)
		if len(script) != node.scriptLen {
			fmt.Println("SCRIPT", node.DrawTree())

		}
		require.Equal(t, len(script), node.scriptLen)
	}

	require.NoError(t, scanner.Err())
}

// Is supposed to test for miniscripts with timelock mixing in `after` (same expression contains
// both time-based and block-based timelocks). This unit test is not testing this currently, see
// https://github.com/rust-bitcoin/rust-miniscript/issues/514.
func TestConflictFromAlloy(t *testing.T) {
	file, err := os.Open("testdata/conflict_from_alloy.txt")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		miniscript, expectedType, found := strings.Cut(line, " ")
		require.True(t, found, "malformed test on line %d: %s", i, line)
		i++
		assert.NoError(t,
			checkMiniscript(miniscript, expectedType),
			"failure on line %d: %s", i, line)
	}

	require.NoError(t, scanner.Err())
}

func testRedeem(
	miniscript string,
	lookupVar func(identifier string) ([]byte, error),
	sequence uint32,
	sign func(pubKey []byte, hash []byte) (signature []byte, available bool),
	preimage func(hashFunc string, hash []byte) (preimage []byte, available bool),
) error {
	// We construct a p2wsh(<miniscript>) UTXO, which we will spend with a satisfaction generated
	// from the miniscript.

	node, err := Parse(miniscript)
	if err != nil {
		return err
	}
	err = node.IsSane()
	if err != nil {
		return err
	}
	err = node.ApplyVars(lookupVar)
	if err != nil {
		return err
	}
	log.Println("tree for miniscript", miniscript)
	log.Printf("\n%s", node.DrawTree())

	log.Println("script:", scriptStr(node, false))
	// Create the script.
	witnessScript, err := node.Script()
	if err != nil {
		return err
	}

	// Create the p2wsh(<script>) UTXO.
	addr, err := btcutil.NewAddressWitnessScriptHash(chainhash.HashB(witnessScript), &chaincfg.TestNet3Params)
	if err != nil {
		return err
	}

	utxoAmount := int64(999799)
	if err != nil {
		return err
	}
	utxoPkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

	// Our test spend is a 1-input 1-output transaction. The input is spends the miniscript
	// UTXO. The output is an arbitrary output - we use a OP_RETURN burn output.

	burnPkScript, err := txscript.NullDataScript(nil)
	if err != nil {
		return err
	}

	// Dummy prevout hash.
	hash, err := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		return err
	}
	txInput := wire.NewTxIn(&wire.OutPoint{Hash: *hash}, nil, nil)
	txInput.Sequence = sequence

	transaction := wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{txInput},
		TxOut:    []*wire.TxOut{{Value: utxoAmount - 200, PkScript: burnPkScript}},
		LockTime: 0,
	}

	// We only have one input, for which we will execute the script.
	inputIndex := 0
	// We only have one input, so the previous outputs fetcher for the transaction simply returns
	// our UTXO. The previous output is needed as it is signed as part of the the transaction
	// sighash for the input.
	previousOutputs := txscript.NewCannedPrevOutputFetcher(utxoPkScript, utxoAmount)
	// Compute the signature hash to be signed for the first input:
	sigHashes := txscript.NewTxSigHashes(&transaction, previousOutputs)
	signatureHash, err := txscript.CalcWitnessSigHash(
		witnessScript, sigHashes, txscript.SigHashAll, &transaction, inputIndex, utxoAmount)
	if err != nil {
		return err
	}

	// Construct a satisfaction (witness) from the miniscript.
	witness, err := node.Satisfy(&Satisfier{
		CheckOlder: func(locktime uint32) (bool, error) {
			return CheckOlder(locktime, uint32(transaction.Version), transaction.TxIn[inputIndex].Sequence), nil
		},
		CheckAfter: func(locktime uint32) (bool, error) {
			return CheckAfter(locktime, transaction.LockTime, transaction.TxIn[inputIndex].Sequence), nil
		},
		Sign: func(pubKey []byte) ([]byte, bool) {
			signature, available := sign(pubKey, signatureHash)
			if !available {
				return nil, false
			}
			signature = append(signature, byte(txscript.SigHashAll))
			return signature, true
		},
		Preimage: preimage,
	})
	if err != nil {
		return err
	}

	// Put the created witness into the transaction input, then execute the script to test that the
	// UTXO can be spent successfully.

	transaction.TxIn[inputIndex].Witness = wire.TxWitness(append(
		witness, witnessScript,
	))
	engine, err := txscript.NewEngine(
		utxoPkScript, &transaction, inputIndex,
		txscript.StandardVerifyFlags, nil, sigHashes, utxoAmount, previousOutputs)
	if err != nil {
		return err
	}
	err = engine.Execute()
	if err != nil {
		return err
	}

	rawTx := &bytes.Buffer{}
	_ = transaction.BtcEncode(rawTx, 0, wire.WitnessEncoding)
	rawTxHex := hex.EncodeToString(rawTx.Bytes())
	log.Println("raw transaction", rawTxHex)
	return nil
}

func TestRedeem(t *testing.T) {
	//miniscript := "and_v(v:pk(key_1),pk(key_2))"
	//miniscript := "and_b(c:pk_k(key_1),s:pk(key_2))"
	//miniscript := "or_b(pk(key_1),s:pk(key_2))"
	//miniscript := "multi(2,key_1,key_2,key_3)"
	//miniscript := "thresh(1,thresh(2,sha256(926a54995ca48600920a19bf7bc502ca5f2f7d07e6f804c4f00ebf0325084dbc),sc:pk_k(key_2),sc:pk_k(key_3)),sc:pk_k(key_4),sc:pk_k(key_5))"
	//miniscript := "and_v(or_c(multi(2,key_1,key_2,key_3),v:sha256(926a54995ca48600920a19bf7bc502ca5f2f7d07e6f804c4f00ebf0325084dbc)),1)"
	//miniscript := "and_v(v:sha256(e0e77a507412b120f6ede61f62295b1a7b2ff19d3dcc8f7253e51663470c888e),c:pk_k(key_1))"
	//miniscript := "or_d(multi(2,key_1,key_2,key_3),multi(2,key_4,key_5))"
	//miniscript := "or_i(multi(2,key_1,key_2,key_3),multi(2,key_4,key_5))"
	//miniscript := "and_v(v:pk(key_1),or_d(pk(key_2),after(12960)))"
	//miniscript := "or_d(pk(key_1),and_v(v:pk(key_2),older(0)))"
	//miniscript := "or_b(pk(key_1),s:pk(key_2))"
	//miniscript := "andor(pk(key_1),pk(key_2),and_v(v:multi(2,key_3,key_4,key_5),older(2)))"
	//miniscript := "or_b(and_b(pk(key_1),s:pk(key_2)),s:pk(key_3))"
	//miniscript := "or_b(and_b(sha256(e0e77a507412b120f6ede61f62295b1a7b2ff19d3dcc8f7253e51663470c888e),s:pk(key_2)),s:pk(key_3))"

	privKey1, pubKey1 := btcec.PrivKeyFromBytes(
		unhex("22a47fa09a223f2aa079edf85a7c2d4f8720ee63e502ee2869afab7de234b80c"))
	privKey2, pubKey2 := btcec.PrivKeyFromBytes(
		unhex("9106e8d2191b58e6c12f10b70d86ba54396db99ecedffd3c150e72960bd11305"))
	privKey3, pubKey3 := btcec.PrivKeyFromBytes(
		unhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

	// hash of hex(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
	h := unhex("e0e77a507412b120f6ede61f62295b1a7b2ff19d3dcc8f7253e51663470c888e")

	lookupVar := func(identifier string) ([]byte, error) {
		switch identifier {
		case "key_1":
			return pubKey1.SerializeCompressed(), nil
		case "key_2":
			return pubKey2.SerializeCompressed(), nil
		case "key_3":
			return pubKey3.SerializeCompressed(), nil
		case "h":
			return h, nil
		}
		return nil, nil
	}

	sign := func(canSign1, canSign2, canSign3 bool) func(pk []byte, hash []byte) ([]byte, bool) {
		return func(pk []byte, hash []byte) ([]byte, bool) {
			if canSign1 && bytes.Equal(pk, pubKey1.SerializeCompressed()) {
				_ = privKey1
				return ecdsa.Sign(privKey1, hash).Serialize(), true
			}
			if canSign2 && bytes.Equal(pk, pubKey2.SerializeCompressed()) {
				_ = privKey2
				return ecdsa.Sign(privKey2, hash).Serialize(), true
			}
			if canSign3 && bytes.Equal(pk, pubKey3.SerializeCompressed()) {
				_ = privKey3
				return ecdsa.Sign(privKey3, hash).Serialize(), true
			}
			return nil, false
		}
	}
	preimage := func(hasPreimage bool) func(hashFunc string, hash []byte) ([]byte, bool) {
		return func(hashFunc string, hash []byte) ([]byte, bool) {
			if hasPreimage && hashFunc == "sha256" && bytes.Equal(hash, h) {
				return unhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true
			}
			return nil, false
		}
	}

	// A single key
	miniscript := "pk(key_1)"
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), nil))
	// No satisfaction (key_1 missing).
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, false, false), nil))

	// One of two keys (equally likely)
	miniscript = "or_b(pk(key_1),s:pk(key_2))"
	// No satisfaction
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, false, false), nil))
	// key_1 signs
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), nil))
	// key_2 signs
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, true, false), nil))

	// One of two keys (one likely, one unlikely)
	miniscript = "or_d(pk(key_1),pkh(key_2))"
	// No satisfaction
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, false, false), nil))
	// key_1 signs
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), nil))
	// key_2 signs
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, true, false), nil))

	// A user and a 2FA service need to sign off, but after 90 days the user alone is enough
	miniscript = "and_v(v:pk(key_1),or_d(pk(key_2),older(12960)))"
	// No satisfaction
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, false, false), nil))
	// key_1 signs alone before 12960
	require.Error(t,
		testRedeem(miniscript, lookupVar, 12960-1, sign(true, false, false), nil))
	// key_1 signs alone, utxo older than 12960
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 12960, sign(true, false, false), nil))
	// key_2 signs alone before 12960
	require.Error(t,
		testRedeem(miniscript, lookupVar, 12960-1, sign(false, true, false), nil))
	// key_2 signs alone after 12960
	require.Error(t,
		testRedeem(miniscript, lookupVar, 12960, sign(false, true, false), nil))
	// both sign before 12960
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, true, false), nil))

	miniscript = "thresh(3,pk(key_1),s:pk(key_2),s:pk(key_3),sln:older(12960))"
	// All three sign before 12960
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, true, true), nil))
	// Only two or one or no one sign before 12960
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, false, false), nil))
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), nil))
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, true, false), nil))
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, true), nil))
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, true, true), nil))
	// Two sign after 12960
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 12960, sign(true, true, false), nil))
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 12960, sign(true, false, true), nil))
	// One or no one signs after 12960
	require.Error(t,
		testRedeem(miniscript, lookupVar, 12960, sign(true, false, false), nil))
	require.Error(t,
		testRedeem(miniscript, lookupVar, 12960, sign(false, false, false), nil))

	// The BOLT #3 to_local policy
	miniscript = "andor(pk(key_1),older(1008),pk(key_2))"
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), nil))
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 1008, sign(true, false, false), nil))
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, true, false), nil))

	miniscript = "and_v(v:pk(key_1),sha256(h))"
	// key_1 but no preimage
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), preimage(false)))
	// preimage but no key_1
	require.Error(t,
		testRedeem(miniscript, lookupVar, 0, sign(false, false, false), preimage(true)))
	// both key_1 and preimage
	require.NoError(t,
		testRedeem(miniscript, lookupVar, 0, sign(true, false, false), preimage(true)))
}

func TestComputeOpCount(t *testing.T) {
	node, err := Parse("or_i(multi(2,key1,key2,key3),multi(3,key4,key5,key6,key7))")
	require.NoError(t, err)
	require.Equal(t, 9, node.maxOpCount())

	node, err = Parse("thresh(2,or_i(multi(2,key1,key2,key3),multi(3,key4,key5,key6,key7)),s:pk(key8),s:pk(key9))")
	require.NoError(t, err)
	require.Equal(t, 16, node.maxOpCount())

	node, err = Parse("thresh(2,or_d(multi(2,key1,key2,key3),multi(3,key4,key5,key6,key7)),s:pk(key8),s:pk(key9))")
	require.NoError(t, err)
	require.Equal(t, 19, node.maxOpCount())
}
