// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var policyVerbose, softValidation bool

// policyValidateCmd represents the policy_validate command
var policyValidateCmd = &cobra.Command{
	Use:    "validate <path>",
	Short:  "Validate a policy",
	PreRun: requirePath,
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		if ruleList, err := loadPolicy(path); err != nil {
			Fatalf("Validation of policy %s has failed: %s\n", path, err)
		} else {
			var skipped bool
			for _, r := range ruleList {
				if err, skipped = r.Sanitize(softValidation); err != nil {
					if !skipped {
						Fatalf("Validation of policy %s has failed: %s\n", path, err)
					} else {
						if policyVerbose {
							fmt.Printf("Validation of policy %s has been skipped\n", path)
						}
					}
				}
			}
			if policyVerbose {
				if !skipped {
					fmt.Printf("All policy elements in %s are valid.\n", path)
				}
			}

			if printPolicy {
				jsonPolicy, err := json.MarshalIndent(ruleList, "", "  ")
				if err != nil {
					Fatalf("Cannot marshal policy %s: %s\n", path, err)
				}
				fmt.Printf("%s", jsonPolicy)
			}
		}
	},
}

func init() {
	PolicyCmd.AddCommand(policyValidateCmd)
	policyValidateCmd.Flags().BoolVarP(&printPolicy, "print", "", false, "Print policy after validation")
	policyValidateCmd.Flags().BoolVarP(&policyVerbose, "verbose", "v", true, "Enable verbose output")
	policyValidateCmd.Flags().BoolVarP(&softValidation, "soft-validate", "", true, "Enable soft validation, i.e. skip rules that cannot be validated")
}
