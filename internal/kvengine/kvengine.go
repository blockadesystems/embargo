/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package kvengine

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blockadesystems/embargo/internal/shared"
	"github.com/blockadesystems/embargo/internal/storage"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type GetSecretResponse struct {
	Data GetSecretResponseData `json:"data" validate:"required"`
	// LeaseID string                `json:"lease_id" validate:"required"`
	// WrapTTL int64                 `json:"wrap_ttl" validate:"required"`
	// Warnings string               `json:"warnings" validate:"required"`
	// Auth    interface{}           `json:"auth" validate:"required"`
}

type GetSecretResponseData struct {
	Data     interface{} `json:"data" validate:"required"`
	Metadata struct {
		CreatedTime    string            `json:"created_time" validate:"required"`
		CustomMetadata map[string]string `json:"custom_metadata" validate:"required"`
		DeletionTime   string            `json:"deletion_time" validate:"required"`
		Destroyed      bool              `json:"destroyed" validate:"required"`
		Version        int64             `json:"version" validate:"required"`
	} `json:"metadata" validate:"required"`
}

type PostedSecret (struct {
	// Data string `json:"data" validate:"required"`
	Data interface{} `json:"data" validate:"required"`
})

type PostedDeleteSecret (struct {
	Versions []int64 `json:"versions" validate:"required"`
})

type SecretMetadataResponse struct {
	Data shared.SecretMetadata `json:"data" validate:"required"`
}

var blockedBuckets = []string{
	"embargo_sys",
	"embargo_mounts",
	"embargo_tokens",
	"embargo_policies",
}

//
// local functions
//

func fullPathtoMountPath(fullpath string) (string, string, string) {
	// trim the leading slash if it exists
	if fullpath[0] == '/' {
		fullpath = fullpath[1:]
	}

	// remove any url parameters
	if i := strings.Index(fullpath, "?"); i != -1 {
		fullpath = fullpath[:i]
	}

	// remove trailing slash if it exists
	if fullpath[len(fullpath)-1] == '/' {
		fullpath = fullpath[:len(fullpath)-1]
	}

	// split the path into parts
	parts := strings.Split(fullpath, "/")

	// remove parts that match data or config
	// Need to refine this
	if parts[0] == "kv" {
		parts = parts[1:]
	}
	if parts[1] == "data" || parts[1] == "delete" || parts[1] == "undelete" || parts[1] == "destroy" {
		// :mount/data/:key
		// :mount/data/:key

		// remove data
		parts = append(parts[:1], parts[2:]...)

	} else if parts[1] == "metadata" {
		// :mount/metadata
		// :mount/metadata/:key

		// remove metadata
		parts = append(parts[:1], parts[2:]...)

		// if parts len is 1, then the mount is the only part
		if len(parts) == 1 {
			mount := parts[0]
			mountNoSlash := parts[0]
			key := ""
			return mount, mountNoSlash, key
		}
	} else if parts[1] == "config" {
		// :mount/config
		// remove config
		parts = append(parts[:1], parts[2:]...)
		if len(parts) == 1 {
			mount := parts[0]
			mountNoSlash := parts[0]
			key := ""
			return mount, mountNoSlash, key
		}
	}

	// the mount is all the parts except the last
	mount := strings.Join(parts[:len(parts)-1], "/")
	// replace slashes with underscores
	mountNoSlash := strings.Replace(mount, "/", "_", -1)
	// the key is the last part
	key := parts[len(parts)-1]
	return mount, mountNoSlash, key

}

func cleanSecret(secret *shared.Secret, mount *shared.Mounts) shared.Secret {
	// Get the current time
	now := time.Now().Unix()

	// Check if the MaxVersions is less than the current number of versions
	// If it is, then delete the oldest versions until the number of versions is less than MaxVersions
	// If the MaxVersions is 0, then there is no limit
	if secret.Metadata.MaxVersions != 0 {
		if len(secret.Versions) >= int(secret.Metadata.MaxVersions) {
			secret.Versions = secret.Versions[len(secret.Versions)-int(secret.Metadata.MaxVersions):]
		}
	}

	// Loop through the versions and delete any that are older than DeleteVersionAfter
	// If DeleteVersionAfter is "0s", then there is no limit
	if mount.Config.Ttl != "0s" {
		for i, v := range secret.Versions {
			ttl, err := time.ParseDuration(mount.Config.Ttl)
			if err != nil {
				log.Println("failed to parse Ttl")
				log.Println(err)
			}
			deleteTime := v.Metadata.CreatedAt + int64(ttl.Seconds())
			if deleteTime >= now {
				secret.Versions = secret.Versions[i:]
				break
			}
		}
	}
	return *secret
}

func getMountConfig(mount string) (*shared.Mounts, error) {
	// Get the metadata object of the secret
	db := storage.GetStore()

	// Check if the mount exists in the mounts bucket
	mConfig, err := db.ReadKey("embargo_mounts", mount, false)
	if err != nil {
		return nil, err
	}
	mountConfig := new(shared.Mounts)
	err = json.Unmarshal([]byte(mConfig), &mountConfig)
	if err != nil {

		return nil, err
	}

	// Check if the mount is a kv mount
	if mountConfig.BucketType != "kv" {
		err = errors.New("mount is not a kv mount")
		return nil, err
	}

	return mountConfig, nil
}

func getUnmarshalSecret(mountNoSlash string, key string) (*shared.Secret, error) {
	// Get the metadata object of the secret
	db := storage.GetStore()

	// Get the secret
	secretStr, err := db.ReadKey(mountNoSlash, key, true)
	if err != nil {
		return nil, err
	}

	// Unmarshal the secret
	storedSecret := new(shared.Secret)
	err = json.Unmarshal([]byte(secretStr), &storedSecret)
	if err != nil {
		return nil, err
	}

	return storedSecret, nil
}

//
// exported functions
//

func GetKVConfig(c echo.Context) error {
	// get the metadata object of the secret
	// db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the path
	_, mountNoSlash, key := fullPathtoMountPath(c.Request().URL.String())

	// Check if the mount prefix is blocked
	for _, blocked := range blockedBuckets {
		if strings.HasPrefix(mountNoSlash, blocked) {
			return c.JSON(http.StatusBadRequest, "Mount is blocked")
		}
	}

	// Check if the mount exists in the mounts bucket, and if it is a kv mount
	_, err := getMountConfig(mountNoSlash)
	if err != nil {
		logger.Error("failed to get mount config", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusNotFound, err)
	}

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mountNoSlash, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Put the secret metadata into the response object
	responseData := new(SecretMetadataResponse)
	responseData.Data = storedSecret.Metadata

	return c.JSON(http.StatusOK, responseData)
}

func ListKeysforMount(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	_, path, _ := fullPathtoMountPath(c.Request().URL.String())

	// Check if the mount prefix is blocked
	for _, blocked := range blockedBuckets {
		if strings.HasPrefix(path, blocked) {
			return c.JSON(http.StatusBadRequest, "Mount is blocked")
		}
	}

	// Check if the mount exists in the mounts bucket and if it is a kv mount
	_, err := getMountConfig(path)
	if err != nil {
		logger.Error("failed to get mount config", zap.String("key", path))
		return c.JSON(http.StatusNotFound, err)
	}

	// Get the keys
	keys, err := db.ReadAllKeys(path)
	if err != nil {
		logger.Error("failed to read all keys", zap.String("key", path))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Build a response data object that contains a list of keys
	responseData := make(map[string]interface{})
	responseData["data"] = []string{}
	for k := range keys {
		responseData["data"] = append(responseData["data"].([]string), k)
	}

	// Check if the mount has any children
	// If it does, add them to the response data object
	children, err := db.GetMountChildren(path)
	if err != nil {
		logger.Error("failed to get mount children", zap.String("key", path))
		return c.JSON(http.StatusInternalServerError, err)
	}
	if len(children) > 0 {
		responseData["data"] = append(responseData["data"].([]string), children...)
	}

	return c.JSON(http.StatusOK, responseData)
}

func PostKV(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Validate the input
	kv := new(PostedSecret)
	if err := c.Bind(kv); err != nil {
		logger.Error("failed to bind request body", zap.Error(err))
		return c.JSON(http.StatusBadRequest, err)
	}

	// Check that PostedSecret.Data is included in the request
	if kv.Data == nil {
		logger.Error("data object is required")
		return c.JSON(http.StatusBadRequest, "data object is required")
	}

	// Get the mount mountNoSlash and key
	mount, mountNoSlash, key := fullPathtoMountPath(c.Request().URL.String())

	// Check if the mount prefix is blocked
	for _, blocked := range blockedBuckets {
		if strings.HasPrefix(mount, blocked) {
			return c.JSON(http.StatusBadRequest, "Mount is blocked")
		}
	}

	// Check if the mount exists in the mounts bucket and if it is a kv mount
	mountConfig, err := getMountConfig(mountNoSlash)
	if err != nil {
		logger.Error("failed to get mount config", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusNotFound, err)
	}

	// Create a new secret
	storedSecret := new(shared.Secret)

	// Check if the key already exists
	// secretEnc, err := db.ReadKey(mountNoSlash, key)
	secretStr, err := db.ReadKey(mountNoSlash, key, true)
	if err != nil && err.Error() != "not found" {
		logger.Error("failed to read key", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusNotFound, err)
	}

	// If the key exists, unmarshal it
	if secretStr != "" {
		err = json.Unmarshal([]byte(secretStr), &storedSecret)
		if err != nil {
			logger.Error("failed to unmarshal secret", zap.String("key", mountNoSlash+"/"+key))
			return c.JSON(http.StatusInternalServerError, err)
		}
		// cleanup the secret
		newStoredSecret := cleanSecret(storedSecret, mountConfig)
		storedSecret = &newStoredSecret
	} else {
		storedSecret.Metadata.CreatedAt = time.Now().Unix()
		storedSecret.Metadata.Path = mount + "/" + key
		storedSecret.Metadata.MaxVersions = mountConfig.Config.MaxVersions
		storedSecret.Metadata.CustomMetadata = make(map[string]string)
	}

	// get the next version number
	// if the secret is new, then the version is 1
	// if the secret exists, then the version is the current version + 1
	var v int64
	if len(storedSecret.Versions) == 0 {
		v = 1
	} else {
		v = storedSecret.Versions[len(storedSecret.Versions)-1].Metadata.Version + 1
	}

	// Create and add the new version
	secretVersion := new(shared.SecretVersion)
	secretVersion.Data = kv.Data
	secretVersion.Metadata.Version = int64(v)
	secretVersion.Metadata.CreatedAt = time.Now().Unix()
	secretVersion.Metadata.DeletionTime = 0
	secretVersion.Metadata.Destroyed = false
	secretVersion.Metadata.Deleted = false
	secretVersion.Metadata.CustomMetadata = make(map[string]string)
	storedSecret.Versions = append(storedSecret.Versions, *secretVersion)

	// Cleanup the secret
	newStoredSecret := cleanSecret(storedSecret, mountConfig)
	storedSecret = &newStoredSecret

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mountNoSlash, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return the secret
	// Get the index of the latest version and build the response
	latestVersionIndex := len(storedSecret.Versions) - 1
	responseData := new(GetSecretResponseData)
	responseData.Data = make(map[string]interface{})
	responseData.Data = storedSecret.Versions[latestVersionIndex].Data
	responseData.Metadata.CreatedTime = time.Unix(storedSecret.Versions[latestVersionIndex].Metadata.CreatedAt, 0).UTC().Format(time.RFC3339)
	responseData.Metadata.CustomMetadata = storedSecret.Metadata.CustomMetadata
	if storedSecret.Versions[latestVersionIndex].Metadata.DeletionTime != 0 {
		responseData.Metadata.DeletionTime = time.Unix(storedSecret.Versions[latestVersionIndex].Metadata.DeletionTime, 0).UTC().Format(time.RFC3339)
	} else {
		responseData.Metadata.DeletionTime = ""
	}
	responseData.Metadata.Destroyed = storedSecret.Versions[latestVersionIndex].Metadata.Destroyed
	responseData.Metadata.Version = storedSecret.Versions[latestVersionIndex].Metadata.Version
	fullResponseData := new(GetSecretResponse)
	fullResponseData.Data = *responseData
	return c.JSON(http.StatusOK, fullResponseData)
}

func GetKV(c echo.Context) error {
	// db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	_, mountNoSlash, key := fullPathtoMountPath(c.Request().URL.String())
	// Get the request parameters
	version := c.QueryParam("version")

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mountNoSlash, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return the secret
	// Get the index of the latest version and build the response
	var getVersion int64
	if version != "" {
		getVersion, err = strconv.ParseInt(version, 10, 64)
		if err != nil {
			logger.Error("failed to parse version", zap.String("key", mountNoSlash+"/"+key))
			return c.JSON(http.StatusInternalServerError, err)
		}
	} else {
		// If no version is specified, return the latest version that is not deleted
		getVersion = 0
		for _, v := range storedSecret.Versions {
			if !v.Metadata.Deleted {
				getVersion = v.Metadata.Version
			}
		}
	}

	// Return the secret
	// Get the index of the latest version requested and build the response
	// If the version is not found, return a 404
	responseData := new(GetSecretResponseData)
	responseData.Data = make(map[string]interface{})
	for _, v := range storedSecret.Versions {
		if v.Metadata.Version == getVersion {
			// if deleted, set the data to nil
			if v.Metadata.Deleted {
				responseData.Data = nil
			} else {
				responseData.Data = v.Data
			}
			responseData.Metadata.CreatedTime = time.Unix(v.Metadata.CreatedAt, 0).UTC().Format(time.RFC3339)
			responseData.Metadata.CustomMetadata = v.Metadata.CustomMetadata
			if v.Metadata.DeletionTime != 0 {
				responseData.Metadata.DeletionTime = time.Unix(v.Metadata.DeletionTime, 0).UTC().Format(time.RFC3339)
			} else {
				responseData.Metadata.DeletionTime = ""
			}
			responseData.Metadata.Destroyed = v.Metadata.Destroyed
			responseData.Metadata.Version = v.Metadata.Version
			fullResponseData := new(GetSecretResponse)
			fullResponseData.Data = *responseData
			return c.JSON(http.StatusOK, fullResponseData)
		}
	}
	return c.JSON(http.StatusNotFound, err)
}

func DeleteKV(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	_, mountNoSlash, key := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mountNoSlash, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Check if method is delete
	deleteSecret := new(PostedDeleteSecret)
	if c.Request().Method == "DELETE" {
		deleteSecret.Versions = append(deleteSecret.Versions, storedSecret.Versions[len(storedSecret.Versions)-1].Metadata.Version)
	} else {
		// Validate the input
		if err := c.Bind(deleteSecret); err != nil {
			logger.Error("failed to bind request body", zap.Error(err))
			return c.JSON(http.StatusBadRequest, err)
		}
	}

	// Mark the versions as deleted
	for _, v := range deleteSecret.Versions {
		for i, sv := range storedSecret.Versions {
			if sv.Metadata.Version == v {
				storedSecret.Versions[i].Metadata.Deleted = true
				storedSecret.Versions[i].Metadata.DeletionTime = time.Now().Unix()
			}
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mountNoSlash, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return blank updated
	return c.JSON(http.StatusNoContent, "")

}

func UndeleteKV(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	_, mountNoSlash, key := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mountNoSlash, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Validate the input
	deleteSecret := new(PostedDeleteSecret)
	if err := c.Bind(deleteSecret); err != nil {
		logger.Error("failed to bind request body", zap.Error(err))
		return c.JSON(http.StatusBadRequest, err)
	}

	// Set deleted to false for the versions and set the deletion time to 0
	for _, v := range deleteSecret.Versions {
		for i, sv := range storedSecret.Versions {
			if sv.Metadata.Version == v {
				storedSecret.Versions[i].Metadata.Deleted = false
				storedSecret.Versions[i].Metadata.DeletionTime = 0
			}
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mountNoSlash, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return blank updated
	return c.JSON(http.StatusNoContent, "")
}

func DestroyKV(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	_, mountNoSlash, key := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mountNoSlash, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Validate the input
	deleteSecret := new(PostedDeleteSecret)
	if err := c.Bind(deleteSecret); err != nil {
		logger.Error("failed to bind request body", zap.Error(err))
		return c.JSON(http.StatusBadRequest, err)
	}

	// Set destroyed to true for the versions, set the deletion time, and remove the data
	for _, v := range deleteSecret.Versions {
		for i, sv := range storedSecret.Versions {
			if sv.Metadata.Version == v {
				storedSecret.Versions[i].Metadata.Destroyed = true
				storedSecret.Versions[i].Metadata.DeletionTime = time.Now().Unix()
				storedSecret.Versions[i].Data = nil
			}
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mountNoSlash, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mountNoSlash+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return blank updated
	return c.JSON(http.StatusNoContent, "")
}
