package commands

// TODO: This file should be only active with remotesigner buildtags.
// Look at walletrpc_default.go & walletrpc_active.go for reference.

import (
	"encoding/hex"
	"fmt"
	"github.com/lightningnetwork/lnd/lnrpc/remotesignerrpc"
	"strconv"

	"github.com/urfave/cli"
)

var WhitelistAddressCommand = cli.Command{
	Name:      "whitelistaddress",
	Category:  "RemoteSigner",
	Usage:     "Whitelist an address for the remote signer validator.",
	ArgsUsage: "address amount",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "address",
			Usage: "the address to whitelist",
		},
		cli.StringFlag{
			Name:  "amount",
			Usage: "the amount to whitelist for the address",
		},
	},
	Action: actionDecorator(whitelistAddress),
}

func whitelistAddress(ctx *cli.Context) error {
	var (
		address string
		amt     int64
		err     error
	)
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	args := ctx.Args()

	address = ctx.String("address")
	if !ctx.IsSet("address") && args.Present() {
		// TODO: error handling
		address = args.First()
		args = args.Tail()
	}

	amt = ctx.Int64("amt")
	if !ctx.IsSet("amt") && args.Present() {
		amt, err = strconv.ParseInt(args.First(), 10, 64)
		args = args.Tail()
		if err != nil {
			return fmt.Errorf("unable to decode amt argument: %w",
				err)
		}
	}

	req := &remotesignerrpc.WhitelistAddressRequest{
		Address: address,
		Amount:  amt,
	}

	resp, err := client.WhitelistAddress(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

func getRemoteSignerClient(ctx *cli.Context) (
	remotesignerrpc.RemoteSignerClient, func()) {

	conn := getClientConn(ctx, false)
	cleanUp := func() {
		conn.Close()
	}
	return remotesignerrpc.NewRemoteSignerClient(conn), cleanUp
}

/*
func parseBlindedPathCfg(ctx *cli.Context) (*lnrpc.BlindedPathConfig, error) {
	if !ctx.Bool("blind") {
		if ctx.IsSet("min_real_blinded_hops") ||
			ctx.IsSet("num_blinded_hops") ||
			ctx.IsSet("max_blinded_paths") ||
			ctx.IsSet("blinded_path_omit_node") {

			return nil, fmt.Errorf("blinded path options are " +
				"only used if the `--blind` options is set")
		}

		return nil, nil
	}

	var blindCfg lnrpc.BlindedPathConfig

	if ctx.IsSet("min_real_blinded_hops") {
		minNumRealHops := uint32(ctx.Uint("min_real_blinded_hops"))
		blindCfg.MinNumRealHops = &minNumRealHops
	}

	if ctx.IsSet("num_blinded_hops") {
		numHops := uint32(ctx.Uint("num_blinded_hops"))
		blindCfg.NumHops = &numHops
	}

	if ctx.IsSet("max_blinded_paths") {
		maxPaths := uint32(ctx.Uint("max_blinded_paths"))
		blindCfg.MaxNumPaths = &maxPaths
	}

	for _, pubKey := range ctx.StringSlice("blinded_path_omit_node") {
		pubKeyBytes, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}

		blindCfg.NodeOmissionList = append(
			blindCfg.NodeOmissionList, pubKeyBytes,
		)
	}

	return &blindCfg, nil
}

*/

var listWhitelistedAddressesCommand = cli.Command{
	Name:     "listwhitelistedaddresses",
	Category: "RemoteSigner",
	Usage:    "List currently whitelisted addresses.",
	Action:   actionDecorator(listWhitelistedAddresses),
}

func listWhitelistedAddresses(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	resp, err := client.WhitelistedAddresses(
		ctxc, &remotesignerrpc.WhitelistedAddressesRequest{},
	)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

var removeWhitelistedAddressCommand = cli.Command{
	Name:      "removewhitelistedaddress",
	Category:  "RemoteSigner",
	Usage:     "Remove an address from the whitelist.",
	ArgsUsage: "address",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "address",
			Usage: "the currently whitelisted address to " +
				"remove from the whitelist",
		},
	},
	Action: actionDecorator(removeWhitelistedAddress),
}

func removeWhitelistedAddress(ctx *cli.Context) error {
	var (
		address string
		err     error
	)
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	args := ctx.Args()

	address = ctx.String("address")
	if !ctx.IsSet("address") && args.Present() {
		// TODO: error handling
		address = args.First()
		args = args.Tail()
	}

	req := &remotesignerrpc.RemoveWhitelistAddressRequest{
		Address: address,
	}

	resp, err := client.RemoveWhitelistedAddress(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

var WhitelistPaymentHashCommand = cli.Command{
	Name:      "whitelistpaymenthash",
	Category:  "RemoteSigner",
	Usage:     "Whitelist a payment hash for the remote signer validator.",
	ArgsUsage: "paymenthash amount",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "paymenthash",
			Usage: "the payment hash to whitelist",
		},
		cli.StringFlag{
			Name:  "amount",
			Usage: "the amount to whitelist for the payment hash",
		},
	},
	Action: actionDecorator(whitelistPaymentHash),
}

func whitelistPaymentHash(ctx *cli.Context) error {
	var (
		paymentHash []byte
		amt         int64
		err         error
	)
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	args := ctx.Args()

	switch {
	case ctx.IsSet("paymenthash"):
		paymentHash, err = hex.DecodeString(ctx.String("paymenthash"))
	case args.Present():
		paymentHash, err = hex.DecodeString(args.First())
	default:
		return fmt.Errorf("paymenthash argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode paymenthash arg: %w", err)
	}

	amt = ctx.Int64("amt")
	if !ctx.IsSet("amt") && args.Present() {
		amt, err = strconv.ParseInt(args.First(), 10, 64)
		args = args.Tail()
		if err != nil {
			return fmt.Errorf("unable to decode amt argument: %w",
				err)
		}
	}

	req := &remotesignerrpc.WhitelistPaymentHashRequest{
		PaymentHash: paymentHash,
		Amount:      amt,
	}

	resp, err := client.WhitelistPaymentHash(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

var listWhitelistedPaymentHashesCommand = cli.Command{
	Name:     "listwhitelistedpaymenthashes",
	Category: "RemoteSigner",
	Usage:    "List currently whitelisted payment hashes.",
	Action:   actionDecorator(listWhitelistedPaymentHashes),
}

func listWhitelistedPaymentHashes(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	resp, err := client.WhitelistedPaymentHashes(
		ctxc, &remotesignerrpc.WhitelistedPaymentHashesRequest{},
	)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}

var removeWhitelistedPaymentHashCommand = cli.Command{
	Name:      "removewhitelistedpaymenthash",
	Category:  "RemoteSigner",
	Usage:     "Remove a payment hash from the whitelist.",
	ArgsUsage: "paymenthash",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "paymenthash",
			Usage: "the currently whitelisted payment hash to " +
				"remove from the whitelist",
		},
	},
	Action: actionDecorator(lookupInvoice),
}

func removeWhitelistedPaymentHash(ctx *cli.Context) error {
	var (
		paymentHash []byte
		err         error
	)
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	args := ctx.Args()

	switch {
	case ctx.IsSet("paymenthash"):
		paymentHash, err = hex.DecodeString(ctx.String("paymenthash"))
	case args.Present():
		paymentHash, err = hex.DecodeString(args.First())
	default:
		return fmt.Errorf("paymenthash argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode paymenthash arg: %w", err)
	}

	req := &remotesignerrpc.RemoveWhitelistPaymentHashRequest{
		PaymentHash: paymentHash,
	}

	resp, err := client.RemoveWhitelistedPaymentHash(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)

	return nil
}
