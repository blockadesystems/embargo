/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

var mount = new(string)

// kvCmd represents the kv command
var kvCmd = &cobra.Command{
	Use:   "kv",
	Short: "Interact with the KV store",
	Long: `Interact with the KV store. For example:
	embargo kv put --mount=secret foo '{"bar":"baz"}'
	embargo kv get --mount=secret foo`,
	Run: func(cmd *cobra.Command, args []string) {
		// fmt.Println("kv called")
	},
}

func init() {
	rootCmd.AddCommand(kvCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// kvCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// kvCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	kvCmd.PersistentFlags().StringVar(mount, "mount", "", "Mount point")
	kvCmd.MarkFlagRequired("mount")
}
