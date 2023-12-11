/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type inboundData struct {
	Data map[string]interface{} `json:"data"`
}

// putCmd represents the put command
var putCmd = &cobra.Command{
	Use:   "put",
	Short: "Put a key into the KV store",
	Long: `Put a key into the KV store. For example:
	`,
	Run: func(cmd *cobra.Command, args []string) {
		m := *mount
		fmt.Println(m)
		key := args[0]
		data := args[1]

		var dataJSON map[string]interface{}
		// check if the first character is a @ symbol
		if strings.HasPrefix(data, "@") {
			// read the file
			file := strings.TrimPrefix(data, "@")

			// open the file
			f, err := os.Open(file)
			if err != nil {
				fmt.Println(err)
			}
			defer f.Close()

			// read the file
			dataBytes, err := ioutil.ReadAll(f)
			if err != nil {
				fmt.Println(err)
			}

			// convert data to JSON
			err = json.Unmarshal(dataBytes, &dataJSON)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			// convert data to JSON
			err := json.Unmarshal([]byte(data), &dataJSON)
			if err != nil {
				fmt.Println(err)
			}
		}

		// create dataObj
		dataObj := inboundData{Data: dataJSON}

		// split the mount point into parts and set mpoint to the first part
		parts := strings.Split(m, "/")
		mpoint := parts[0]

		// combine the rest of parts and key to get the full path
		path := strings.Join(parts[1:], "/")
		if len(path) > 1 {
			path = fmt.Sprintf("%s/%s", path, key)
		} else {
			path = key
		}

		// get EMBARGO_TOKEN from environment
		token := os.Getenv("EMBARGO_TOKEN")
		// get EMBARGO_SERVER from environment
		server := os.Getenv("EMBARGO_SERVER")

		// build URL
		url := fmt.Sprintf("%s/kv/%s/data/%s", server, mpoint, path)
		println(url)

		// post dataObj to server
		jsonData, err := json.Marshal(dataObj)
		if err != nil {
			fmt.Println(err)
		}
		req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
		if err != nil {
			fmt.Println(err)
		}

		req.Header.Add("X-Embargo-Token", token)
		req.Header.Add("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println(err)
		}
		defer resp.Body.Close()

		// read response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
		}

		// print response
		fmt.Println(string(body))
	},
}

func init() {
	kvCmd.AddCommand(putCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// putCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// putCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
