//go:build !remotesignerrpc
// +build !remotesignerrpc

package commands

import "github.com/urfave/cli"

// remotesignerCommands will return nil for non-remotesignerrpc builds.
func remotesignerCommands() []cli.Command {
	return nil
}
