package itest

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
	"github.com/stretchr/testify/require"
)

var (
	rootKey = "tprv8ZgxMBicQKsPe6jS4vDm2n7s42Q6MpvghUQqMmSKG7bTZvGKtjrcU3" +
		"PGzMNG37yzxywrcdvgkwrr8eYXJmbwdvUNVT4Ucv7ris4jvA7BUmg"

	nodePubKey = "033f55d436d4f7d24aeffb1b976647380f22ebf9e74390e8c76dcff" +
		"9fea0093b7a"

	accounts = []*lnrpc.WatchOnlyAccount{{
		Purpose: waddrmgr.KeyScopeBIP0049Plus.Purpose,
		// We always use the mainnet coin type for our BIP49/84/86
		// addresses!
		CoinType: 0,
		Account:  0,
		Xpub: "tpubDDXEYWvGCTytEF6hBog9p4qr2QBUvJhh4P2wM4qHHv9N489khk" +
			"QoGkBXDVoquuiyBf8SKBwrYseYdtq9j2v2nttPpE8qbuW3sE2MCk" +
			"FPhTq",
	}, {
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		// We always use the mainnet coin type for our BIP49/84/86
		// addresses!
		CoinType: 0,
		Account:  0,
		Xpub: "tpubDDWAWrSLRSFrG1KdqXMQQyTKYGSKLKaY7gxpvK7RdV3e3Dkhvu" +
			"W2GgsFvsPN4RGmuoYtUgZ1LHZE8oftz7T4mzc1BxGt5rt8zJcVQi" +
			"KTPPV",
	}, {
		Purpose: waddrmgr.KeyScopeBIP0086.Purpose,
		// We always use the mainnet coin type for our BIP49/84/86
		// addresses!
		CoinType: 0,
		Account:  0,
		Xpub: "tpubDDtdXpdJFU2zFKWHJwe5M2WtYtcV7qSWtKohT9VP9zarNSwKnm" +
			"kwDQawsu1vUf9xwXhUDYXbdUqpcrRTn9bLyW4BAVRimZ4K7r5o1J" +
			"S924u",
	}}
)

type remoteSignerTestCase struct {
	name       string
	randomSeed bool
	sendCoins  bool
	commitType lnrpc.CommitmentType
	fn         func(tt *lntest.HarnessTest,
		wo, carol *node.HarnessNode)
}

func getRemoteSignerTestCases(ht *lntest.HarnessTest) []remoteSignerTestCase {
	return []remoteSignerTestCase{{
		name:       "random seed",
		randomSeed: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			// Nothing more to test here.
		},
	}, {
		name: "account import",
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runWalletImportAccountScenario(
				tt, walletrpc.AddressType_WITNESS_PUBKEY_HASH,
				carol, wo,
			)
		},
	}, {
		name:      "basic channel open close",
		sendCoins: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runBasicChannelCreationAndUpdates(tt, wo, carol)
		},
	}, {
		name:      "channel funding input types",
		sendCoins: false,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runChannelFundingInputTypes(tt, carol, wo)
		},
	}, {
		name:      "async payments",
		sendCoins: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runAsyncPayments(tt, wo, carol, nil)
		},
	}, {
		name:      "async payments taproot",
		sendCoins: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			commitType := lnrpc.CommitmentType_SIMPLE_TAPROOT

			runAsyncPayments(
				tt, wo, carol, &commitType,
			)
		},
		commitType: lnrpc.CommitmentType_SIMPLE_TAPROOT,
	}, {
		name: "shared key",
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runDeriveSharedKey(tt, wo)
		},
	}, {
		name:      "bumpfee",
		sendCoins: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runBumpFee(tt, wo)
		},
	}, {
		name:       "psbt",
		randomSeed: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runPsbtChanFunding(
				tt, carol, wo, false,
				lnrpc.CommitmentType_LEGACY,
			)
			runSignPsbtSegWitV0P2WKH(tt, wo)
			runSignPsbtSegWitV1KeySpendBip86(tt, wo)
			runSignPsbtSegWitV1KeySpendRootHash(tt, wo)
			runSignPsbtSegWitV1ScriptSpend(tt, wo)

			// The above tests all make sure we can sign for keys
			// that aren't in the wallet. But we also want to make
			// sure we can fund and then sign PSBTs from our wallet.
			runFundAndSignPsbt(ht, wo)
		},
	}, {
		name:      "sign output raw",
		sendCoins: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runSignOutputRaw(tt, wo)
		},
	}, {
		name:      "sign verify msg",
		sendCoins: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			runSignVerifyMessage(tt, wo)
		},
	}, {
		name:       "taproot",
		sendCoins:  true,
		randomSeed: true,
		fn: func(tt *lntest.HarnessTest, wo, carol *node.HarnessNode) {
			testTaprootSendCoinsKeySpendBip86(tt, wo)
			testTaprootComputeInputScriptKeySpendBip86(tt, wo)
			testTaprootSignOutputRawScriptSpend(tt, wo)
			testTaprootSignOutputRawKeySpendBip86(tt, wo)
			testTaprootSignOutputRawKeySpendRootHash(tt, wo)

			muSig2Versions := []signrpc.MuSig2Version{
				signrpc.MuSig2Version_MUSIG2_VERSION_V040,
				signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2,
			}
			for _, version := range muSig2Versions {
				testTaprootMuSig2KeySpendRootHash(
					tt, wo, version,
				)
				testTaprootMuSig2ScriptSpend(tt, wo, version)
				testTaprootMuSig2KeySpendBip86(tt, wo, version)
				testTaprootMuSig2CombinedLeafKeySpend(
					tt, wo, version,
				)
			}
		},
	}}
}

// testInboundRemoteSigner tests that a watch-only wallet can use a remote
// signing wallet to perform any signing or ECDH operations. The test
// specifically uses an inbound remote signer, meaning that the watch-only node
// will make an outbound connection to the remote signer.
func testInboundRemoteSigner(ht *lntest.HarnessTest) {
	prepareTest := func(st *lntest.HarnessTest,
		subTest remoteSignerTestCase) (*node.HarnessNode,
		*node.HarnessNode, *node.HarnessNode) {

		// Signer is our signing node and has the wallet with the full
		// master private key. We test that we can create the watch-only
		// wallet from the exported accounts but also from a static key
		// to make sure the derivation of the account public keys is
		// correct in both cases.
		password := []byte("itestpassword")
		var (
			signerNodePubKey  = nodePubKey
			watchOnlyAccounts = deriveCustomScopeAccounts(ht.T)
			signer            *node.HarnessNode
			err               error
		)
		if !subTest.randomSeed {
			signer = st.RestoreNodeWithSeed(
				"Signer", nil, password, nil, rootKey, 0, nil,
			)
		} else {
			signer = st.NewNode("Signer", nil)
			signerNodePubKey = signer.PubKeyStr

			rpcAccts := signer.RPC.ListAccounts(
				&walletrpc.ListAccountsRequest{},
			)

			watchOnlyAccounts, err = walletrpc.AccountsToWatchOnly(
				rpcAccts.Accounts,
			)
			require.NoError(st, err)
		}

		var commitArgs []string
		if subTest.commitType == lnrpc.CommitmentType_SIMPLE_TAPROOT {
			commitArgs = lntest.NodeArgsForCommitType(
				subTest.commitType,
			)
		}

		// WatchOnly is the node that has a watch-only wallet and uses
		// the Signer node for any operation that requires access to
		// private keys.
		watchOnly := st.NewNodeWatchOnly(
			"WatchOnly", append([]string{
				"--remotesigner.enable",
				"--remotesigner.signerrole=watchonly-inbound",
				fmt.Sprintf(
					"--remotesigner.rpchost=localhost:%d",
					signer.Cfg.RPCPort,
				),
				fmt.Sprintf(
					"--remotesigner.tlscertpath=%s",
					signer.Cfg.TLSCertPath,
				),
				fmt.Sprintf(
					"--remotesigner.macaroonpath=%s",
					signer.Cfg.AdminMacPath,
				),
			}, commitArgs...),
			password, &lnrpc.WatchOnly{
				MasterKeyBirthdayTimestamp: 0,
				MasterKeyFingerprint:       nil,
				Accounts:                   watchOnlyAccounts,
			},
		)

		resp := watchOnly.RPC.GetInfo()
		require.Equal(st, signerNodePubKey, resp.IdentityPubkey)

		if subTest.sendCoins {
			st.FundCoins(btcutil.SatoshiPerBitcoin, watchOnly)
			ht.AssertWalletAccountBalance(
				watchOnly, "default",
				btcutil.SatoshiPerBitcoin, 0,
			)
		}

		carol := st.NewNode("carol", commitArgs)
		st.EnsureConnected(watchOnly, carol)

		return signer, watchOnly, carol
	}

	for _, testCase := range getRemoteSignerTestCases(ht) {
		subTest := testCase

		success := ht.Run(subTest.name, func(tt *testing.T) {
			// Skip the cleanup here as no standby node is used.
			st := ht.Subtest(tt)

			_, watchOnly, carol := prepareTest(st, subTest)
			subTest.fn(st, watchOnly, carol)
		})

		if !success {
			return
		}
	}
}

// testOutboundRemoteSigner tests that a watch-only wallet can use a remote
// signing wallet to perform any signing or ECDH operations. The test
// specifically uses an outbound remote signer, meaning that the remote signer
// node will make an outbound connection to the watch-only node.
func testOutboundRemoteSigner(ht *lntest.HarnessTest) {
	prepareTest := func(st *lntest.HarnessTest,
		subTest remoteSignerTestCase) (*node.HarnessNode,
		*node.HarnessNode, *node.HarnessNode) {

		// Signer is our signing node and has the wallet with the full
		// master private key. We test that we can create the watch-only
		// wallet from the exported accounts but also from a static key
		// to make sure the derivation of the account public keys is
		// correct in both cases.
		password := []byte("itestpassword")
		var (
			signerNodePubKey  = nodePubKey
			watchOnlyAccounts = deriveCustomScopeAccounts(ht.T)
			signer            *node.HarnessNode
			err               error
		)

		var commitArgs []string
		if subTest.commitType == lnrpc.CommitmentType_SIMPLE_TAPROOT {
			commitArgs = lntest.NodeArgsForCommitType(
				subTest.commitType,
			)
		}

		// WatchOnly is the node that has a watch-only wallet and uses
		// the Signer node for any operation that requires access to
		// private keys. We use the outbound signer type here, meaning
		// that the watch-only node expects the signer to make an
		// outbound connection to it.
		watchOnly := st.CreateNewNode(
			"WatchOnly", append([]string{
				"--remotesigner.enable",
				"--remotesigner.signerrole=watchonly-outbound",
				"--remotesigner.timeout=30s",
				"--remotesigner.requesttimeout=30s",
			}, commitArgs...),
			password, true,
		)

		// As the signer node will make an outbound connection to the
		// watch-only node, we must specify the watch-only node's RPC
		// connection details in the signer's configuration.
		signerArgs := []string{
			"--remotesigner.signerrole=signer-outbound",
			"--remotesigner.timeout=30s",
			"--remotesigner.requesttimeout=10s",
			fmt.Sprintf(
				"--remotesigner.rpchost=localhost:%d",
				watchOnly.Cfg.RPCPort,
			),
			fmt.Sprintf(
				"--remotesigner.tlscertpath=%s",
				watchOnly.Cfg.TLSCertPath,
			),
			fmt.Sprintf(
				"--remotesigner.macaroonpath=%s",
				watchOnly.Cfg.AdminMacPath,
			),
		}

		if !subTest.randomSeed {
			signer = st.RestoreNodeWithSeed(
				"Signer", signerArgs, password, nil, rootKey, 0,
				nil,
			)
		} else {
			signer = st.NewNode("Signer", signerArgs)
			signerNodePubKey = signer.PubKeyStr

			rpcAccts := signer.RPC.ListAccounts(
				&walletrpc.ListAccountsRequest{},
			)

			watchOnlyAccounts, err = walletrpc.AccountsToWatchOnly(
				rpcAccts.Accounts,
			)
			require.NoError(st, err)
		}

		// As the watch-only node will not fully start until the signer
		// node connects to it, we need to start the watch-only node
		// after having started the signer node.
		st.StartWatchOnly(watchOnly, "WatchOnly", password,
			&lnrpc.WatchOnly{
				MasterKeyBirthdayTimestamp: 0,
				MasterKeyFingerprint:       nil,
				Accounts:                   watchOnlyAccounts,
			},
		)

		resp := watchOnly.RPC.GetInfo()
		require.Equal(st, signerNodePubKey, resp.IdentityPubkey)

		if subTest.sendCoins {
			st.FundCoins(btcutil.SatoshiPerBitcoin, watchOnly)
			ht.AssertWalletAccountBalance(
				watchOnly, "default",
				btcutil.SatoshiPerBitcoin, 0,
			)
		}

		carol := st.NewNode("carol", commitArgs)
		st.EnsureConnected(watchOnly, carol)

		return signer, watchOnly, carol
	}

	for _, testCase := range getRemoteSignerTestCases(ht) {
		subTest := testCase

		success := ht.Run(subTest.name, func(tt *testing.T) {
			// Skip the cleanup here as no standby node is used.
			st := ht.Subtest(tt)

			_, watchOnly, carol := prepareTest(st, subTest)
			subTest.fn(st, watchOnly, carol)
		})

		if !success {
			return
		}
	}
}

// testOutboundRSMacaroonEnforcement tests that a valid macaroon including
// the `remotesigner` entity is required to connect to a watch-only node that
// uses an outbound remote signer, while the watch-only node is in the state
// where it waits for the signer to connect.
func testOutboundRSMacaroonEnforcement(ht *lntest.HarnessTest) {
	// Ensure that the watch-only node uses a configuration that requires an
	// outbound remote signer during startup.
	watchOnlyArgs := []string{
		"--remotesigner.enable",
		"--remotesigner.signerrole=watchonly-outbound",
		"--remotesigner.timeout=15s",
		"--remotesigner.requesttimeout=15s",
	}

	// Create the watch-only node. Note that we require authentication for
	// the watch-only node, as we want to test that the macaroon enforcement
	// works as expected.
	watchOnly := ht.CreateNewNode("WatchOnly", watchOnlyArgs, nil, false)

	startChan := make(chan error)

	// Start the watch-only node in a goroutine as it requires a remote
	// signer to connect before it can fully start.
	go func() {
		startChan <- watchOnly.Start(ht.Context())
	}()

	// Wait and ensure that the watch-only node reaches the state where
	// it waits for the remote signer to connect, as this is the state where
	// we want to test the macaroon enforcement.
	err := wait.Predicate(func() bool {
		if watchOnly.RPC == nil {
			return false
		}

		state, err := watchOnly.RPC.State.GetState(
			ht.Context(), &lnrpc.GetStateRequest{},
		)
		if err != nil {
			return false
		}

		return state.State == lnrpc.WalletState_ALLOW_REMOTE_SIGNER
	}, 5*time.Second)
	require.NoError(ht, err)

	// Set up a connection to the watch-only node. However, instead of using
	// the watch-only node's admin macaroon, we'll use the invoice macaroon.
	// The connection should not be allowed using this macaroon because it
	// lacks the `remotesigner` entity required when the signer node
	// connects to the watch-only node.
	streamFeeder := rpcwallet.NewStreamFeeder(
		watchOnly.Cfg.RPCAddr(), watchOnly.Cfg.InvoiceMacPath,
		watchOnly.Cfg.TLSCertPath, 10*time.Second,
	)

	stream, cleanup, err := streamFeeder.GetStream(ht.Context())
	require.NoError(ht, err)

	defer cleanup()

	// Since we're using an unauthorized macaroon, we should expect to be
	// denied access to the watch-only node.
	_, err = stream.Recv()
	require.ErrorContains(ht, err, "permission denied")

	// Finally, connect a real signer to the watch-only node so that
	// it can start up properly.
	signerArgs := []string{
		"--remotesigner.signerrole=signer-outbound",
		"--remotesigner.timeout=30s",
		"--remotesigner.requesttimeout=10s",
		fmt.Sprintf(
			"--remotesigner.rpchost=localhost:%d",
			watchOnly.Cfg.RPCPort,
		),
		fmt.Sprintf(
			"--remotesigner.tlscertpath=%s",
			watchOnly.Cfg.TLSCertPath,
		),
		fmt.Sprintf(
			"--remotesigner.macaroonpath=%s",
			watchOnly.Cfg.AdminMacPath, // An authorized macaroon.
		),
	}

	_ = ht.NewNode("Signer", signerArgs)

	// Finally, wait and ensure that the watch-only node is able to start
	// up properly.
	err = <-startChan
	require.NoError(ht, err, "Shouldn't error on watch-only node startup")
}

// deriveCustomScopeAccounts derives the first 255 default accounts of the custom lnd
// internal key scope.
func deriveCustomScopeAccounts(t *testing.T) []*lnrpc.WatchOnlyAccount {
	allAccounts := make([]*lnrpc.WatchOnlyAccount, 0, 255+len(accounts))
	allAccounts = append(allAccounts, accounts...)

	extendedRootKey, err := hdkeychain.NewKeyFromString(rootKey)
	require.NoError(t, err)

	path := []uint32{
		keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
		harnessNetParams.HDCoinType + hdkeychain.HardenedKeyStart,
	}
	coinTypeKey, err := derivePath(extendedRootKey, path)
	require.NoError(t, err)
	for idx := uint32(0); idx <= 255; idx++ {
		accountPath := []uint32{idx + hdkeychain.HardenedKeyStart}
		accountKey, err := derivePath(coinTypeKey, accountPath)
		require.NoError(t, err)

		accountXPub, err := accountKey.Neuter()
		require.NoError(t, err)

		allAccounts = append(allAccounts, &lnrpc.WatchOnlyAccount{
			Purpose:  keychain.BIP0043Purpose,
			CoinType: harnessNetParams.HDCoinType,
			Account:  idx,
			Xpub:     accountXPub.String(),
		})
	}

	return allAccounts
}

// derivePath derives the given path from an extended key.
func derivePath(key *hdkeychain.ExtendedKey, path []uint32) (
	*hdkeychain.ExtendedKey, error) {

	var (
		currentKey = key
		err        error
	)
	for _, pathPart := range path {
		currentKey, err = currentKey.Derive(pathPart)
		if err != nil {
			return nil, err
		}
	}

	return currentKey, nil
}
