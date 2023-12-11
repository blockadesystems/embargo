/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/blockadesystems/embargo/internal/shared"
	"github.com/spf13/cobra"
)

var jsonOutput = new(bool)
var version = new(string)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a key from the KV store",
	Long: `Get a key from the KV store. For example:
	embargo kv get --mount=secret foo`,
	Run: func(cmd *cobra.Command, args []string) {
		// get EMBARGO_TOKEN from environment
		token := os.Getenv("EMBARGO_TOKEN")
		// get EMBARGO_SERVER from environment
		server := os.Getenv("EMBARGO_SERVER")

		// split the path into parts
		// parts := strings.Split(args[0], "/")

		// set the mount point to the first part and the key to the rest
		// mount := parts[0]
		// key := strings.Join(parts[1:], "/")
		key := strings.Join(args, "/")
		m := *mount

		// build URL
		url := fmt.Sprintf("%s/kv/%s/data/%s", server, m, key)

		// add version to URL if provided
		if *version != "" {
			url = fmt.Sprintf("%s?version=%s", url, *version)
		}

		// get data from server
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println(err)
		}
		req.Header.Add("X-Embargo-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
		}

		// read data from response
		// var data map[string]interface{}
		// err = json.NewDecoder(resp.Body).Decode(&data)
		// if err != nil {
		// 	fmt.Println(err)
		// }

		// unmarshal the resp body into shared.KvResponse
		var kvResp shared.KvResponse
		err = json.Unmarshal(body, &kvResp)
		if err != nil {
			fmt.Println(err)
		}

		if *jsonOutput {
			// check if data is nil
			if kvResp.Data.Data == nil {
				// create a not found JSON response message
				notFound := map[string]string{
					"message": "not found",
				}
				// print not found JSON response
				jsonData, err := json.MarshalIndent(notFound, "", "  ")
				if err != nil {
					fmt.Println(err)
				}
				// pretty print JSON
				fmt.Println(string(jsonData))
			} else {
				// print data as JSON
				jsonData, err := json.MarshalIndent(kvResp, "", "  ")
				if err != nil {
					fmt.Println(err)
				}
				// pretty print JSON
				fmt.Println(string(jsonData))

			}
		} else {
			// check if data is nil
			if kvResp.Data.Data == nil {
				// print not found message
				fmt.Println("no data found")
			} else {
				// // format data.metadata as table and print
				fmt.Println("Metadata:")
				fmt.Printf("%-20s %-20s\n", "Key", "Value")
				fmt.Printf("%-20s %-20s\n", "----", "-----")
				fmt.Printf("%-20s %-20s\n", "created_time", kvResp.Data.Metadata.CreatedTime)
				fmt.Printf("%-20s %-20s\n", "deletion_time", kvResp.Data.Metadata.DeletionTime)
				fmt.Printf("%-20s %-20v\n", "destroyed", kvResp.Data.Metadata.Destroyed)
				fmt.Printf("%-20s %-20v\n", "version", kvResp.Data.Metadata.Version)
				// fmt.Printf("%-20s %-20v\n", "custom_metadata", kvResp.Data.Metadata.CustomMetadata)
				fmt.Printf("\n")
				// format data and print data.data
				fmt.Println("Data:")
				fmt.Printf("%-20s %-20s\n", "Key", "Value")
				fmt.Printf("%-20s %-20s\n", "----", "-----")
				// Print the key and value of data.data interface
				if rec, ok := kvResp.Data.Data.(map[string]interface{}); ok {
					for k, v := range rec {
						fmt.Printf("%-20s %v\n", k, v)
					}
				}
			}
		}
	},
}

func init() {
	kvCmd.AddCommand(getCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	getCmd.Flags().BoolVarP(jsonOutput, "json", "j", false, "Print output as JSON")
	getCmd.Flags().StringVarP(version, "version", "v", "", "Version of key to retrieve")
}
