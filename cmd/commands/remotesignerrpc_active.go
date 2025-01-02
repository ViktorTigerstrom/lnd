//go:build remotesignerrpc
// +build remotesignerrpc

package commands

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc/remotesignerrpc"

	"github.com/urfave/cli"
)

var WhitelistAddressCommand = cli.Command{
	Name:      "add",
	Usage:     "Whitelist an address for the remote signer validator.",
	ShortName: "a",
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

	chainParams, err := networkParams(ctx)
	if err != nil {
		return err
	}

	args := ctx.Args()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg()+ctx.NumFlags() != 2 {
		return cli.ShowCommandHelp(ctx, "add")
	}

	switch {
	case ctx.IsSet("address"):
		address = ctx.String("address")
	case args.Present():
		address = args.First()
		args = args.Tail()
	default:
		return fmt.Errorf("address argument missing")
	}

	_, err = btcutil.DecodeAddress(
		address, chainParams,
	)
	if err != nil {
		return fmt.Errorf("error parsing address: %w", err)
	}

	switch {
	case ctx.IsSet("amount"):
		amt, err = strconv.ParseInt(ctx.String("amount"), 10, 64)
	case args.Present():
		amt, err = strconv.ParseInt(args.First(), 10, 64)
		args = args.Tail()
	default:
		return fmt.Errorf("amount argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode amount argument: %w", err)
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

var listWhitelistedAddressesCommand = cli.Command{
	Name:      "list",
	Usage:     "List currently whitelisted addresses.",
	ShortName: "l",
	Action:    actionDecorator(listWhitelistedAddresses),
}

func listWhitelistedAddresses(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg()+ctx.NumFlags() != 0 {
		return cli.ShowCommandHelp(ctx, "list")
	}

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
	Name:      "remove",
	Usage:     "Remove an address from the whitelist.",
	ShortName: "r",
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

	chainParams, err := networkParams(ctx)
	if err != nil {
		return err
	}

	args := ctx.Args()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg()+ctx.NumFlags() != 1 {
		return cli.ShowCommandHelp(ctx, "remove")
	}

	switch {
	case ctx.IsSet("address"):
		address = ctx.String("address")
	case args.Present():
		address = args.First()
		args = args.Tail()
	default:
		return fmt.Errorf("address argument missing")
	}

	_, err = btcutil.DecodeAddress(
		address, chainParams,
	)
	if err != nil {
		return fmt.Errorf("error parsing address: %w", err)
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
	Name:      "add",
	Usage:     "Whitelist a payment hash for the remote signer validator.",
	ShortName: "a",
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

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.

	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	args := ctx.Args()

	if ctx.NArg()+ctx.NumFlags() != 2 {
		return cli.ShowCommandHelp(ctx, "add")
	}

	switch {
	case ctx.IsSet("paymenthash"):
		paymentHash, err = hex.DecodeString(ctx.String("paymenthash"))
	case args.Present():
		paymentHash, err = hex.DecodeString(args.First())
		args = args.Tail()
	default:
		return fmt.Errorf("paymenthash argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode paymenthash arg: %w", err)
	}
	if len(paymentHash) != 32 {
		return fmt.Errorf("the length of the paymenthash must be " +
			"exactly 32 bytes (64 chars)")
	}

	switch {
	case ctx.IsSet("amount"):
		amt, err = strconv.ParseInt(ctx.String("amount"), 10, 64)
	case args.Present():
		amt, err = strconv.ParseInt(args.First(), 10, 64)
		args = args.Tail()
	default:
		return fmt.Errorf("amount argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode amount argument: %w", err)
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
	Name:      "list",
	Usage:     "List currently whitelisted payment hashes.",
	ShortName: "l",
	Action:    actionDecorator(listWhitelistedPaymentHashes),
}

func listWhitelistedPaymentHashes(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRemoteSignerClient(ctx)
	defer cleanUp()

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg()+ctx.NumFlags() != 0 {
		return cli.ShowCommandHelp(ctx, "list")
	}

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
	Name:      "remove",
	Usage:     "Remove a payment hash from the whitelist.",
	ShortName: "r",
	ArgsUsage: "paymenthash",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "paymenthash",
			Usage: "the currently whitelisted payment hash to " +
				"remove from the whitelist",
		},
	},
	Action: actionDecorator(removeWhitelistedPaymentHash),
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

	// Display the command's help message if we do not have the expected
	// number of arguments/flags.
	if ctx.NArg()+ctx.NumFlags() != 1 {
		return cli.ShowCommandHelp(ctx, "remove")
	}

	switch {
	case ctx.IsSet("paymenthash"):
		paymentHash, err = hex.DecodeString(ctx.String("paymenthash"))
	case args.Present():
		paymentHash, err = hex.DecodeString(args.First())
		args = args.Tail()
	default:
		return fmt.Errorf("paymenthash argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode paymenthash arg: %w", err)
	}
	if len(paymentHash) != 32 {
		return fmt.Errorf("the length of the paymenthash must be " +
			"exactly 32 bytes (64 chars)")
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

var addressWhitelistCommands = cli.Command{
	Name:        "addresswhitelist",
	Category:    "Address whitelist",
	Usage:       "Interact with the address whitelist",
	ShortName:   "aw",
	Description: "",
	Subcommands: []cli.Command{
		WhitelistAddressCommand,
		listWhitelistedAddressesCommand,
		removeWhitelistedAddressCommand,
	},
}

var paymentHashWhitelistCommands = cli.Command{
	Name:        "paymenthashwhitelist",
	Category:    "Payment hash whitelist",
	Usage:       "Interact with the payment hash whitelist",
	ShortName:   "pw",
	Description: "",
	Subcommands: []cli.Command{
		WhitelistPaymentHashCommand,
		listWhitelistedPaymentHashesCommand,
		removeWhitelistedPaymentHashCommand,
	},
}

// remotesignerCommands will return the set of commands to enable for
// remotesignerrpc builds.
func remotesignerCommands() []cli.Command {
	return []cli.Command{
		{
			Name:        "remotesigner",
			Category:    "Remote Signer",
			Usage:       "Interact with the validator's whitelists",
			Description: "",
			Subcommands: []cli.Command{
				addressWhitelistCommands,
				paymentHashWhitelistCommands,
			},
		},
	}
}
