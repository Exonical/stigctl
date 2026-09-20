//go:build !linux

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newApplyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "apply <baseline>",
		Short: "Apply STIG remediation with Yip (Linux only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("local STIG remediation is supported only on Linux")
		},
	}
}

func newValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <baseline>",
		Short: "Validate a STIG baseline with Goss (Linux only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("local STIG validation is supported only on Linux; use scan --inventory with --remote-binary")
		},
	}
}
