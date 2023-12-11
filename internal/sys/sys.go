/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package sys

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blockadesystems/embargo/internal/encryption"
	"github.com/blockadesystems/embargo/internal/shamir"
	"github.com/blockadesystems/embargo/internal/shared"
	"github.com/blockadesystems/embargo/internal/storage"
	"github.com/blockadesystems/embargo/internal/tokenauth"
	"github.com/google/uuid"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type UnsealData struct {
	Threshold int
	Shares    int
	Keys      []string
}

type UnsealRequest struct {
	Key   string    `json:"key" validate:"optional"`
	Reset bool      `json:"reset" validate:"optional"`
	Nonce uuid.UUID `json:"nonce" validate:"optional"`
}

type UnsealResponse struct {
	Sealed    bool `json:"sealed"`
	Threshold int  `json:"threshold"`
	Number    int  `json:"number"`
	Progress  int  `json:"progress"`
}

type RekeyData struct {
	Started   bool      `json:"started"`
	Threshold int       `json:"threshold"`
	Shares    int       `json:"shares"`
	Progress  int       `json:"progress"`
	Required  int       `json:"required"`
	Nonce     uuid.UUID `json:"nonce"`
	Keys      []string
}

type PostedMount struct {
	Type        string             `json:"type" validate:"required"`
	Description string             `json:"description"`
	Config      shared.MountConfig `json:"config"`
	Options     PostedMountOptions `json:"options"`
}

type PostedMountOptions struct {
	MaxVersions        int    `json:"max_versions"`
	DeleteVersionAfter string `json:"delete_version_after"`
}

type ReturnMounts struct {
	// Data  []shared.Mounts `json:"data" validate:"required"`
	Data  map[string]interface{} `json:"data" validate:"required"`
	Total int                    `json:"total" validate:"required"`
}

// type KVOptions struct {
// 	MaxVersions int `json:"max_versions"`
// }

func randomString(n int) string {
	var seedRand = rand.New(rand.NewSource(time.Now().UnixNano()))

	var letters []rune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~!@#$%^&*(){}?><|:;][=-_+")
	alphabetSize := len(letters)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		// ch := letters[rand.Intn(alphabetSize)]
		ch := letters[seedRand.Intn(alphabetSize)]
		sb.WriteRune(ch)
	}
	s := sb.String()
	return s
}

func StartSys() {
	db := storage.GetStore()

	// Check if system has been initialized, if value does not exist then add it
	i, err := db.ReadKey("embargo_sys", "initialized", false)
	if err != nil {
		log.Println("Error reading initialized key", err)
		// panic(err)
	}
	// If the key does not exist, create it
	if i == "" {
		err = db.CreateKey("embargo_sys", "initialized", "false", false)
		if err != nil {
			log.Println("Error creating initialized key", err)
			panic(err)
		}
		i = "false"
	}

	initialized, err := strconv.ParseBool(i)
	if err != nil {
		log.Println("Error reading initialized key", err)
		panic(err)
	}

	// no point in continuing if the system is not initialized
	if !initialized {
		log.Println("System not initialized")
		return
	}

	// Load vars from env
	autoUnseal := os.Getenv("EMBARGO_AUTO_UNSEAL")
	if len(autoUnseal) == 0 {
		autoUnseal = "false"
	}
	autoUnsealBool, err := strconv.ParseBool(autoUnseal)
	if autoUnsealBool {
		// Get the unseal keys from env
		unsealKeys := os.Getenv("EMBARGO_UNSEAL_KEYS")
		if unsealKeys == "" {
			log.Println("Error reading unseal keys from env")
			panic(err)
		}
		// Split the keys and trim whitespace
		keys := strings.Split(unsealKeys, ",")
		for i, key := range keys {
			keys[i] = strings.TrimSpace(key)
		}
		// Unseal the system
		err = unsealSystem(keys)
		if err != nil {
			log.Println("Error unsealing system", err)
			panic(err)
		}
	}

	// Get unseal data from the db
	u, err := db.ReadKey("embargo_sys", "unseal", false)
	if err != nil {
		log.Println("Error reading unseal key", err)
		panic(err)
	}
	var unsealData UnsealData
	json.Unmarshal([]byte(u), &unsealData)

	// Reset unseal data
	unsealData.Keys = []string{}
	data, err := json.Marshal(unsealData)
	if err != nil {
		log.Println("Error marshalling unseal data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "unseal", string(data))
	if err != nil {
		log.Println("Error updating unseal key", err)
		panic(err)
	}

	// Reset rekey_in_progress
	var rekey RekeyData
	rekey.Started = false
	rekey.Threshold = 0
	rekey.Shares = 0
	rekey.Progress = 0
	rekey.Required = 0
	rekey.Nonce = uuid.Nil
	rekey.Keys = []string{}
	rekeyJSON, err := json.Marshal(rekey)
	if err != nil {
		log.Println("Error marshalling rekey data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "rekey", string(rekeyJSON))
	if err != nil {
		log.Println("Error updating rekey key", err)
		panic(err)
	}
}

func InitStatus(c echo.Context) error {
	db := storage.GetStore()

	// Check if system has been initialized
	i, err := db.ReadKey("embargo_sys", "initialized", false)
	if err != nil {
		log.Println("Error reading initialized key", err)
		panic(err)
	}
	initialized, err := strconv.ParseBool(i)
	if err != nil {
		log.Println("Error reading initialized key", err)
		panic(err)
	}

	// Create the response data
	returnData := make(map[string]interface{})
	returnData["initialized"] = initialized

	return c.JSON(http.StatusOK, returnData)
}

func InitSys(r shared.InitSysRequest) (shared.InitSysResponse, error) {
	db := storage.GetStore()
	var res shared.InitSysResponse

	// Check if the system has already been initialized. If so, return an error
	i, err := db.ReadKey("embargo_sys", "initialized", false)
	if err != nil {
		return res, err
	}
	initialized, err := strconv.ParseBool(i)
	if err != nil {
		return res, err
	}
	if initialized {
		return res, errors.New("system already initialized")
	}

	// Set the unseal data and update the database
	unsealData := UnsealData{
		Threshold: r.Threshold,
		Shares:    r.Shares,
		Keys:      []string{},
	}
	data, err := json.Marshal(unsealData)
	if err != nil {
		log.Println("Error marshalling unseal data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "unseal", string(data))
	if err != nil {
		log.Println("Error updating unseal key", err)
		panic(err)
	}

	// Generate the root key
	FutureRootKey := randomString(32)
	encryption.RootKey = FutureRootKey
	shares, err := shamir.Split([]byte(FutureRootKey), r.Shares, r.Threshold)
	if err != nil {
		log.Println("Error splitting root key", err)
		panic(err)
	}

	encodedShares := make([]string, len(shares))
	for i, share := range shares {
		data := make([]byte, b64.StdEncoding.EncodedLen(len(share)))
		b64.StdEncoding.Encode(data, share)
		encodedShares[i] = string(data)
	}

	// Hash and store the root key
	hashedRootKey, err := bcrypt.GenerateFromPassword([]byte(FutureRootKey), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing root key", err)
		panic(err)
	}
	err = db.CreateKey("embargo_sys", "root_key", string(hashedRootKey), false)
	if err != nil {
		log.Println("Error creating root key", err)
		panic(err)
	}

	// Create encryption key
	encryptionKey := shared.EncryptionKey{
		Id:  uuid.New(),
		Key: randomString(32),
	}
	encryption.EncKeys.ActiveKey = encryptionKey

	// Create the encryption key list
	encryption.EncKeys.OldKeys = []shared.EncryptionKey{}

	// Store the encryption key in the database
	encryptionKeyJSON, err := json.Marshal(encryption.EncKeys)
	if err != nil {
		log.Println("Error marshalling encryption key", err)
		panic(err)
	}
	encryptedData, err := encryption.EncryptKeys(string(encryptionKeyJSON))
	if err != nil {
		log.Println("Error encrypting encryption key", err)
		panic(err)
	}
	err = db.CreateKey("embargo_sys", "encryption_key", string(encryptedData), false)
	if err != nil {
		log.Println("Error creating encryption key", err)
		panic(err)
	}

	// Update initialized to true
	err = db.UpdateKey("embargo_sys", "initialized", "true")
	if err != nil {
		log.Println("Error updating initialized key", err)
		panic(err)
	}

	// Create a root embargo token

	token, key := tokenauth.CreateEmbargoToken("root", 0, true, true, true, uuid.Nil, []uuid.UUID{}, make(map[string]string))

	// Store the token in the database
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		log.Println("Error marshalling token", err)
		panic(err)
	}
	err = db.CreateKey("embargo_tokens", token.TokenID.String(), string(tokenJSON), false)
	if err != nil {
		log.Println("Error creating token", err)
		panic(err)
	}

	// unset the root key and encryption key
	encryption.RootKey = ""
	encryption.EncKeys = shared.EncryptionKeyList{}

	// Create the response data
	res.Shares = encodedShares
	res.RootToken = key

	return res, nil
}

func InitSysPost(c echo.Context) error {
	// secret_shares and secret_threshold are required
	// secret_shares must be greater than or equal to secret_threshold

	// Get the request data
	r := new(shared.InitSysRequest)
	if err := c.Bind(r); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if r.Threshold == 0 {
		return c.JSON(http.StatusBadRequest, "secret_threshold required and must be greater than 0")
	}
	if r.Shares == 0 {
		return c.JSON(http.StatusBadRequest, "secret_shares required and must be greater than 0")
	}
	if r.Shares < r.Threshold {
		return c.JSON(http.StatusBadRequest, "secret_shares must be greater than or equal to secret_threshold")
	}

	// Process the request
	res, err := InitSys(*r)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	returnData := make(map[string]interface{})
	returnData["message"] = "The system has been initialized with " + strconv.Itoa(r.Shares) + " shares and a threshold of " + strconv.Itoa(r.Threshold) + ". The shares are listed below. Please store them in a safe place. When the system starts, you will need to unseal it with " + strconv.Itoa(r.Threshold) + " of the " + strconv.Itoa(r.Shares) + " shares. The system does not store the shares or the generated root key. Without at least " + strconv.Itoa(r.Threshold) + " shares, the system cannot be unsealed."
	returnData["threshold"] = r.Threshold
	returnData["shares"] = res.Shares
	returnData["rootToken"] = res.RootToken

	return c.JSON(http.StatusOK, returnData)
}

func SealStatus() bool {
	if encryption.RootKey == "" {
		return true
	} else {
		return false
	}
}

func GetSealStatus(c echo.Context) error {
	db := storage.GetStore()

	// Check if system has been initialized
	i, err := db.ReadKey("embargo_sys", "initialized", false)
	if err != nil {
		log.Println("Error reading initialized key", err)
		panic(err)
	}
	initialized, err := strconv.ParseBool(i)
	if err != nil {
		log.Println("Error reading initialized key", err)
		panic(err)
	}
	if !initialized {
		return c.JSON(http.StatusBadRequest, "system not initialized")
	}

	// Check if system is sealed
	if encryption.RootKey == "" {
		// Create the response data
		returnData := make(map[string]interface{})
		returnData["sealed"] = true

		return c.JSON(http.StatusOK, returnData)
	} else {
		// Create the response data
		returnData := make(map[string]interface{})
		returnData["sealed"] = false

		return c.JSON(http.StatusOK, returnData)
	}
}

func unsealSystem(keys []string) error {
	var shares [][]byte

	for _, key := range keys {
		k := make([]byte, b64.StdEncoding.DecodedLen(len(key)))
		n, err := b64.StdEncoding.Decode(k, []byte(key))
		if err != nil {
			log.Println("Error decoding share", err)
			panic(err)
		}
		shares = append(shares, k[:n])
	}

	// Try and combine the keys
	// If it fails, return an error
	rk, err := shamir.Combine(shares)
	if err != nil {
		return err
	}

	// Get the hashed root key from the database
	// See if the root key matches the stored hash
	// If it does, set the root key
	// If it doesn't, return an error
	db := storage.GetStore()
	h, err := db.ReadKey("embargo_sys", "root_key", false)
	if err != nil {
		log.Println("Error reading root key", err)
		panic(err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(h), rk)
	if err != nil {
		return err
	}

	encryption.RootKey = string(rk)

	// Get the encryption key from the database
	// Decrypt the encryption key
	// If it fails, return an error
	e, err := db.ReadKey("embargo_sys", "encryption_key", false)
	if err != nil {
		log.Println("Error reading encryption key", err)
		panic(err)
	}
	decryptedData, err := encryption.DecryptKeys([]byte(e))
	if err != nil {
		log.Println("Error decrypting encryption key", err)
		panic(err)
	}
	tmp := new(shared.EncryptionKeyList)
	err = json.Unmarshal([]byte(decryptedData), tmp)
	if err != nil {
		log.Println("Error unmarshalling encryption key", err)
		panic(err)
	}
	encryption.EncKeys = *tmp

	return nil
}

func Unseal(c echo.Context) error {
	db := storage.GetStore()

	// Get unseal data from the db
	u, err := db.ReadKey("embargo_sys", "unseal", false)
	if err != nil {
		log.Println("Error reading unseal key", err)
		panic(err)
	}
	var unsealData UnsealData
	json.Unmarshal([]byte(u), &unsealData)

	// Get sealed status
	sealed := true
	if encryption.RootKey == "" {
		sealed = true
	} else {
		sealed = false
	}

	// Get the request data
	r := new(UnsealRequest)
	if err := c.Bind(r); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// If the system is not sealed, return an error
	if !sealed {
		return c.JSON(http.StatusBadRequest, "system is not sealed")
	}

	// Check if request includes reset flag
	// If so, reset unseal data and return
	if r.Reset {
		// Reset unseal data
		unsealData.Keys = []string{}
		data, err := json.Marshal(unsealData)
		if err != nil {
			log.Println("Error marshalling unseal data", err)
			panic(err)
		}
		err = db.UpdateKey("embargo_sys", "unseal", string(data))
		if err != nil {
			log.Println("Error updating unseal key", err)
			panic(err)
		}

		// Set response data
		returnData := make(map[string]interface{})
		returnData["sealed"] = sealed
		returnData["threshold"] = unsealData.Threshold
		returnData["number"] = len(unsealData.Keys)
		returnData["progress"] = strconv.Itoa(0) + "/" + strconv.Itoa(unsealData.Threshold)

		return c.JSON(http.StatusOK, returnData)
	}

	// Check if the request includes a key
	// If not, return an error
	if r.Key == "" {
		return c.JSON(http.StatusBadRequest, "key required")
	}

	// Validate the key provided
	// If it is not valid, return an error
	k := make([]byte, b64.StdEncoding.DecodedLen(len(r.Key)))
	_, err = b64.StdEncoding.Decode(k, []byte(r.Key))
	if err != nil {
		return c.JSON(http.StatusBadRequest, "invalid key")
	}

	// Add the key to the unseal data
	unsealData.Keys = append(unsealData.Keys, r.Key)
	data, err := json.Marshal(unsealData)
	if err != nil {
		log.Println("Error marshalling unseal data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "unseal", string(data))
	if err != nil {
		log.Println("Error updating unseal key", err)
		panic(err)
	}

	// Check if we have enough keys to unseal the system
	// If so, unseal the system
	// If not, return the current unseal status
	if len(unsealData.Keys) >= unsealData.Threshold {

		// Try and combine the keys
		// If it fails, reset the unseal data and return
		// rk, err := shamir.Combine(keys)
		err := unsealSystem(unsealData.Keys)
		if err != nil {
			// Reset the unseal data
			unsealData.Keys = []string{}
			data, err := json.Marshal(unsealData)
			if err != nil {
				log.Println("Error marshalling unseal data", err)
				panic(err)
			}
			err = db.UpdateKey("embargo_sys", "unseal", string(data))
			if err != nil {
				log.Println("Error updating unseal key", err)
				panic(err)
			}

			// Set response data
			returnData := make(map[string]interface{})
			returnData["sealed"] = sealed
			returnData["threshold"] = unsealData.Threshold
			returnData["number"] = len(unsealData.Keys)
			returnData["progress"] = strconv.Itoa(0) + "/" + strconv.Itoa(unsealData.Threshold)

			return c.JSON(http.StatusOK, returnData)
		}

		// RootKey = string(rk)

		if err != nil {
			// Reset the unseal data
			unsealData.Keys = []string{}
			data, err := json.Marshal(unsealData)
			if err != nil {
				log.Println("Error marshalling unseal data", err)
				panic(err)
			}
			err = db.UpdateKey("embargo_sys", "unseal", string(data))
			if err != nil {
				log.Println("Error updating unseal key", err)
				panic(err)
			}

			// Set response data
			returnData := make(map[string]interface{})
			returnData["sealed"] = sealed
			returnData["threshold"] = unsealData.Threshold
			returnData["number"] = len(unsealData.Keys)
			returnData["progress"] = strconv.Itoa(0) + "/" + strconv.Itoa(unsealData.Threshold)

			return c.JSON(http.StatusOK, returnData)
		}

		sealed = false

		// Set response data
		returnData := make(map[string]interface{})
		returnData["sealed"] = sealed
		returnData["threshold"] = unsealData.Threshold
		returnData["number"] = len(unsealData.Keys)
		returnData["progress"] = strconv.Itoa(len(unsealData.Keys)) + "/" + strconv.Itoa(unsealData.Threshold)

		return c.JSON(http.StatusOK, returnData)
	} else {
		// Set response data
		returnData := make(map[string]interface{})
		returnData["sealed"] = sealed
		returnData["threshold"] = unsealData.Threshold
		returnData["number"] = len(unsealData.Keys)
		returnData["progress"] = strconv.Itoa(len(unsealData.Keys)) + "/" + strconv.Itoa(unsealData.Threshold)

		return c.JSON(http.StatusOK, returnData)
	}
}

func RekeyInitGet(c echo.Context) error {
	db := storage.GetStore()

	// Check if a rekey is in progress
	// If so, return the status
	// If not, return an error

	// Get the rekey data from the database
	r, err := db.ReadKey("embargo_sys", "rekey", false)
	if err != nil {
		log.Println("Error reading rekey key", err)
		panic(err)
	}
	var rekeyData RekeyData
	json.Unmarshal([]byte(r), &rekeyData)

	// Check if a rekey is in progress
	if rekeyData.Started {
		// Create the response data
		returnData := make(map[string]interface{})
		returnData["nonce"] = rekeyData.Nonce
		returnData["started"] = rekeyData.Started
		returnData["threshold"] = rekeyData.Threshold
		returnData["shares"] = rekeyData.Shares
		returnData["progress"] = rekeyData.Progress
		returnData["required"] = rekeyData.Required

		return c.JSON(http.StatusOK, returnData)
	} else {
		return c.JSON(http.StatusBadRequest, "rekey not in progress")
	}
}

func RekeyInitPost(c echo.Context) error {
	db := storage.GetStore()

	// Check if a rekey is in progress
	// If so, return an error
	// If not, start the rekey

	// Get the rekey data from the database
	r, err := db.ReadKey("embargo_sys", "rekey", false)
	if err != nil {
		log.Println("Error reading rekey key", err)
		panic(err)
	}
	var rekeyData RekeyData
	json.Unmarshal([]byte(r), &rekeyData)

	// Check if a rekey is in progress
	if rekeyData.Started {
		return c.JSON(http.StatusBadRequest, "rekey already in progress")
	}

	// Get the request data
	rq := new(shared.InitSysRequest)
	if err := c.Bind(rq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if rq.Threshold == 0 {
		return c.JSON(http.StatusBadRequest, "secret_threshold required and must be greater than 0")
	}
	if rq.Shares == 0 {
		return c.JSON(http.StatusBadRequest, "secret_shares required and must be greater than 0")
	}
	if rq.Shares < rq.Threshold {
		return c.JSON(http.StatusBadRequest, "secret_shares must be greater than or equal to secret_threshold")
	}

	// Get unseal data from the db
	u, err := db.ReadKey("embargo_sys", "unseal", false)
	if err != nil {
		log.Println("Error reading unseal key", err)
		panic(err)
	}
	var unsealData UnsealData
	json.Unmarshal([]byte(u), &unsealData)

	// Set the rekey data and update the database
	rekeyData.Nonce = uuid.New()
	rekeyData.Started = true
	rekeyData.Threshold = rq.Threshold
	rekeyData.Shares = rq.Shares
	rekeyData.Progress = 0
	rekeyData.Required = unsealData.Threshold
	rekeyData.Keys = []string{}
	data, err := json.Marshal(rekeyData)
	if err != nil {
		log.Println("Error marshalling rekey data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "rekey", string(data))
	if err != nil {
		log.Println("Error updating rekey key", err)
		panic(err)
	}

	// Create the response data
	returnData := make(map[string]interface{})
	returnData["nonce"] = rekeyData.Nonce
	returnData["started"] = rekeyData.Started
	returnData["threshold"] = rekeyData.Threshold
	returnData["shares"] = rekeyData.Shares
	returnData["progress"] = rekeyData.Progress
	returnData["required"] = rekeyData.Required

	return c.JSON(http.StatusOK, returnData)

}

func RekeyInitDelete(c echo.Context) error {
	db := storage.GetStore()

	// Get the rekey data from the database
	r, err := db.ReadKey("embargo_sys", "rekey", false)
	if err != nil {
		log.Println("Error reading rekey key", err)
		panic(err)
	}
	var rekeyData RekeyData
	json.Unmarshal([]byte(r), &rekeyData)

	// Check if a rekey is in progress
	if !rekeyData.Started {
		return c.JSON(http.StatusBadRequest, "rekey not in progress")
	}

	// Reset rekey_in_progress
	rekeyData.Started = false
	rekeyData.Threshold = 0
	rekeyData.Shares = 0
	rekeyData.Progress = 0
	rekeyData.Required = 0
	rekeyData.Nonce = uuid.Nil
	rekeyData.Keys = []string{}
	rekeyJSON, err := json.Marshal(rekeyData)
	if err != nil {
		log.Println("Error marshalling rekey data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "rekey", string(rekeyJSON))
	if err != nil {
		log.Println("Error updating rekey key", err)
		panic(err)
	}

	// Create the response data
	returnData := make(map[string]interface{})
	returnData["message"] = "Rekey canceled"

	return c.JSON(http.StatusOK, returnData)
}

func RekeyUpdatePost(c echo.Context) error {
	db := storage.GetStore()

	// Get the rekey data from the database
	r, err := db.ReadKey("embargo_sys", "rekey", false)
	if err != nil {
		log.Println("Error reading rekey key", err)
		panic(err)
	}

	var rekeyData RekeyData
	json.Unmarshal([]byte(r), &rekeyData)

	// Check if a rekey is in progress
	if !rekeyData.Started {
		return c.JSON(http.StatusBadRequest, "rekey not in progress")
	}

	// Get the request data
	rq := new(UnsealRequest)
	if err := c.Bind(rq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Check if the request includes a key
	// If not, return an error
	if rq.Key == "" {
		return c.JSON(http.StatusBadRequest, "key required")
	}

	// Check if the nonce matches
	// If not, return an error
	if rq.Nonce != rekeyData.Nonce {
		return c.JSON(http.StatusBadRequest, "invalid nonce")
	}

	// Validate the key provided
	// If it is not valid, return an error
	k := make([]byte, b64.StdEncoding.DecodedLen(len(rq.Key)))
	_, err = b64.StdEncoding.Decode(k, []byte(rq.Key))
	if err != nil {
		return c.JSON(http.StatusBadRequest, "invalid key")
	}

	// Add the key to the rekey data
	rekeyData.Keys = append(rekeyData.Keys, rq.Key)
	rekeyData.Progress = len(rekeyData.Keys)
	data, err := json.Marshal(rekeyData)
	if err != nil {
		log.Println("Error marshalling rekey data", err)
		panic(err)
	}
	err = db.UpdateKey("embargo_sys", "rekey", string(data))
	if err != nil {
		log.Println("Error updating rekey key", err)
		panic(err)
	}

	// Check if we have enough keys to rekey the system
	// If so, rekey the system
	// If not, return the current rekey status
	if len(rekeyData.Keys) >= rekeyData.Threshold {

		// Try and combine the keys
		// If it fails, reset the rekey data and return
		err := unsealSystem(rekeyData.Keys)
		if err != nil {
			// Reset the rekey data
			rekeyData.Started = false
			rekeyData.Threshold = 0
			rekeyData.Shares = 0
			rekeyData.Progress = 0
			rekeyData.Required = 0
			rekeyData.Nonce = uuid.Nil
			rekeyData.Keys = []string{}
			rekeyJSON, err := json.Marshal(rekeyData)
			if err != nil {
				log.Println("Error marshalling rekey data", err)
				panic(err)
			}
			err = db.UpdateKey("embargo_sys", "rekey", string(rekeyJSON))
			if err != nil {
				log.Println("Error updating rekey key", err)
				panic(err)
			}

			// Set response data
			returnData := make(map[string]interface{})
			returnData["started"] = rekeyData.Started
			returnData["threshold"] = rekeyData.Threshold
			returnData["shares"] = rekeyData.Shares
			returnData["progress"] = rekeyData.Progress
			returnData["required"] = rekeyData.Required

			return c.JSON(http.StatusOK, returnData)
		}

		// Generate the root key
		FutureRootKey := randomString(32)
		encryption.RootKey = FutureRootKey
		shares, err := shamir.Split([]byte(FutureRootKey), rekeyData.Shares, rekeyData.Threshold)
		if err != nil {
			log.Println("Error splitting root key", err)
			panic(err)
		}

		encodedShares := make([]string, len(shares))
		for i, share := range shares {
			data := make([]byte, b64.StdEncoding.EncodedLen(len(share)))
			b64.StdEncoding.Encode(data, share)
			encodedShares[i] = string(data)
		}

		// Hash and store the root key
		hashedRootKey, err := bcrypt.GenerateFromPassword([]byte(FutureRootKey), bcrypt.DefaultCost)
		if err != nil {
			log.Println("Error hashing root key", err)
			panic(err)
		}
		err = db.CreateKey("embargo_sys", "root_key", string(hashedRootKey), false)
		if err != nil {
			log.Println("Error creating root key", err)
			panic(err)
		}

		// Encrypt the encryption key with the new root key
		encryptionKeyJSON, err := json.Marshal(encryption.EncKeys)
		if err != nil {
			log.Println("Error marshalling encryption key", err)
			panic(err)
		}
		encryptedData, err := encryption.EncryptKeys(string(encryptionKeyJSON))
		if err != nil {
			log.Println("Error encrypting encryption key", err)
			panic(err)
		}
		err = db.CreateKey("embargo_sys", "encryption_key", string(encryptedData), false)
		if err != nil {
			log.Println("Error creating encryption key", err)
			panic(err)
		}

		// Reset rekey_in_progress
		rq := rekeyData
		rekeyData.Started = false
		rekeyData.Threshold = 0
		rekeyData.Shares = 0
		rekeyData.Progress = 0
		rekeyData.Required = 0
		rekeyData.Nonce = uuid.Nil
		rekeyData.Keys = []string{}
		rekeyJSON, err := json.Marshal(rekeyData)
		if err != nil {
			log.Println("Error marshalling rekey data", err)
			panic(err)
		}
		err = db.UpdateKey("embargo_sys", "rekey", string(rekeyJSON))
		if err != nil {
			log.Println("Error updating rekey key", err)
			panic(err)
		}

		// Create the response data
		returnData := make(map[string]interface{})
		returnData["message"] = "The system has been rekeyed with " + strconv.Itoa(rq.Shares) + " shares and a threshold of " + strconv.Itoa(rq.Threshold) + ". The shares are listed below. Please store them in a safe place. When the system starts, you will need to unseal it with " + strconv.Itoa(rq.Threshold) + " of the " + strconv.Itoa(rq.Shares) + " shares. The system does not store the shares or the generated root key. Without at least " + strconv.Itoa(rq.Threshold) + " shares, the system cannot be unsealed."
		returnData["threshold"] = rq.Threshold
		returnData["shares"] = encodedShares

		return c.JSON(http.StatusOK, returnData)
	} else {
		// Set response data
		returnData := make(map[string]interface{})
		returnData["started"] = rekeyData.Started
		returnData["threshold"] = rekeyData.Threshold
		returnData["shares"] = rekeyData.Shares
		returnData["progress"] = rekeyData.Progress
		returnData["required"] = rekeyData.Required

		return c.JSON(http.StatusOK, returnData)
	}
}

//
// Mounts
//

func GetMount(c echo.Context) error {
	db := storage.GetStore()

	// Get the mount path
	path := c.Param("mount")

	// Remove trailing slash
	if path[len(path)-1:] == "/" {
		path = path[:len(path)-1]
	}

	// Get the mount from the database
	mount, err := db.ReadKey("embargo_mounts", path, false)
	if err != nil {
		log.Println(err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Unmarshal the mount
	var m shared.Mounts
	err = json.Unmarshal([]byte(mount), &m)
	if err != nil {
		log.Println(err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Create the response data
	returnData := make(map[string]interface{})
	returnData["description"] = m.Description
	returnData["type"] = m.BucketType
	returnData["path"] = m.Path
	returnData["config"] = m.Config
	returnData["created_at"] = time.Unix(m.CreatedAt, 0).UTC().Format(time.RFC3339)
	returnData["updated_at"] = time.Unix(m.UpdatedAt, 0).UTC().Format(time.RFC3339)

	return c.JSON(http.StatusOK, returnData)
}

func CreateMount(c echo.Context) error {
	db := storage.GetStore()

	// Get the request data
	r := new(PostedMount)
	if err := c.Bind(r); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get the mount path
	path := c.Param("mount")

	// Remove trailing slash
	if path[len(path)-1:] == "/" {
		path = path[:len(path)-1]
	}

	// replace slashes with underscores
	pathNoSlash := strings.ReplaceAll(path, "/", "_")

	// Check if the mount already exists
	k, _ := db.ReadKey("embargo_mounts", pathNoSlash, false)
	if k != "" {
		return c.JSON(http.StatusBadRequest, "mount already exists")
	}

	// Check if the mount bucket already exists
	bucketExists := db.BucketExists(pathNoSlash)
	if bucketExists {
		return c.JSON(http.StatusBadRequest, "mount bucket already exists")
	}

	// Need to validate config or set defaults
	if r.Config.Ttl == "" {
		r.Config.Ttl = "0s"
	}
	if r.Config.MaxVersions == 0 {
		r.Config.MaxVersions = 0
	}

	// Create a mount
	mount := shared.Mounts{
		Path:        path,
		BucketType:  r.Type,
		Description: r.Description,
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Config:      r.Config,
	}

	// Store the mount in the embargo_mounts bucket
	mountJSON, err := json.Marshal(mount)
	if err != nil {
		log.Println("Error marshalling mount", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey("embargo_mounts", pathNoSlash, string(mountJSON), false)
	if err != nil {
		log.Println("Error creating mount", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Create the mount bucket
	err = db.CreateBucket(pathNoSlash)
	if err != nil {
		log.Println("Error creating mount bucket", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Create the response data
	rMount := make(map[string]interface{})
	rMount["description"] = mount.Description
	rMount["type"] = mount.BucketType
	rMount["path"] = mount.Path
	rMount["config"] = mount.Config
	rMount["created_at"] = time.Unix(mount.CreatedAt, 0).UTC().Format(time.RFC3339)
	rMount["updated_at"] = time.Unix(mount.UpdatedAt, 0).UTC().Format(time.RFC3339)

	returnData := make(map[string]interface{})
	returnData["message"] = "Mount created"
	returnData["mount"] = rMount

	return c.JSON(http.StatusOK, returnData)
}

func Get_mounts(c echo.Context) error {
	db := storage.GetStore()

	mounts, err := db.ReadAllKeys("embargo_mounts")
	if err != nil {
		log.Println(err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return the mounts
	var returnMounts ReturnMounts
	returnMounts.Data = make(map[string]interface{})
	returnMounts.Total = len(mounts)
	for k, v := range mounts {
		var m shared.Mounts
		err = json.Unmarshal([]byte(v), &m)
		if err != nil {
			log.Println(err)
			return c.JSON(http.StatusInternalServerError, err)
		}
		tmp := make(map[string]interface{})
		tmp["description"] = m.Description
		tmp["type"] = m.BucketType
		tmp["config"] = m.Config
		tmp["created_at"] = time.Unix(m.CreatedAt, 0).UTC().Format(time.RFC3339)
		tmp["updated_at"] = time.Unix(m.UpdatedAt, 0).UTC().Format(time.RFC3339)
		returnMounts.Data[k+"/"] = tmp
	}

	return c.JSON(http.StatusOK, returnMounts)
}

func GetMountTune(c echo.Context) error {
	db := storage.GetStore()

	// Get the mount path
	path := c.Param("mount")

	// Remove trailing slash
	if path[len(path)-1:] == "/" {
		path = path[:len(path)-1]
	}

	// replace slashes with underscores
	pathNoSlash := strings.ReplaceAll(path, "/", "_")

	// Check if the mount exists
	mount, _ := db.ReadKey("embargo_mounts", pathNoSlash, false)
	if mount == "" {
		return c.JSON(http.StatusBadRequest, "mount does not exist")
	}

	// Get the mount config
	var m shared.Mounts
	err := json.Unmarshal([]byte(mount), &m)
	if err != nil {
		log.Println(err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Create the response data
	returnData := shared.MountConfig{
		Ttl:         m.Config.Ttl,
		MaxVersions: m.Config.MaxVersions,
	}

	return c.JSON(http.StatusOK, returnData)
}

func PostMountTune(c echo.Context) error {
	db := storage.GetStore()

	// Get the mount path
	mountStr := c.Param("mount")

	// Remove trailing slash
	if mountStr[len(mountStr)-1:] == "/" {
		mountStr = mountStr[:len(mountStr)-1]
	}

	// Check if the mount exists
	mount, _ := db.ReadKey("embargo_mounts", mountStr, false)
	if mount == "" {
		return c.JSON(http.StatusBadRequest, "mount does not exist")
	}

	// Get the request data
	r := new(PostedMountOptions)
	if err := c.Bind(r); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get the mount config
	var m shared.Mounts
	err := json.Unmarshal([]byte(mount), &m)
	if err != nil {
		log.Println(err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Need to validate config or set defaults
	if r.MaxVersions == 0 {
		r.MaxVersions = 0
	}

	// Update the mount config
	m.Config.MaxVersions = int64(r.MaxVersions)
	m.Config.Ttl = r.DeleteVersionAfter

	// Store the mount in the embargo_mounts bucket
	mountJSON, err := json.Marshal(m)
	if err != nil {
		log.Println("Error marshalling mount", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	err = db.UpdateKey("embargo_mounts", mountStr, string(mountJSON))
	if err != nil {
		log.Println("Error updating mount", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Send a blank response
	return c.JSON(http.StatusOK, "")

}
