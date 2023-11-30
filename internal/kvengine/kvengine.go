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

type SecretMetadataListResponse struct {
	Data SecretMetadataListData `json:"data" validate:"required"`
}

type SecretMetadataListData struct {
	CreatedAt          string                 `json:"created_at" validate:"required"`
	CurrentVersion     int64                  `json:"current_version" validate:"required"`
	DeleteVersionAfter int64                  `json:"delete_version_after" validate:"required"`
	MaxVersions        int64                  `json:"max_versions" validate:"required"`
	OldestVersion      int64                  `json:"oldest_version" validate:"required"`
	CustomMetadata     map[string]string      `json:"custom_metadata" validate:"required"`
	Versions           map[string]VersionData `json:"versions" validate:"required"`
}

type VersionData struct {
	CreatedTime string `json:"created_time" validate:"required"`
	DeletedTime string `json:"deleted_time" validate:"required"`
	Destroyed   bool   `json:"destroyed" validate:"required"`
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
	//return mount, key, subpaths
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
		// kv/:mount/data/:key
		parts = parts[1:]
	}

	// remove the action part of the path
	parts = append(parts[:1], parts[2:]...)
	mount := parts[0]
	key := parts[1]
	subpath := ""
	if len(parts) > 2 {
		subpath = strings.Join(parts[2:], "/")
	}

	return mount, key, subpath
}

func cleanSecret(secret *shared.Secret, mount *shared.Mounts, versions []shared.SecretVersion) []shared.SecretVersion {
	// Get the current time
	now := time.Now().Unix()

	// Check if the MaxVersions is less than the current number of versions
	// If it is, then delete the oldest versions until the number of versions is less than MaxVersions
	// If the MaxVersions is 0, then there is no limit
	if secret.Metadata.MaxVersions != 0 {
		if len(versions) >= int(secret.Metadata.MaxVersions) {
			versions = versions[len(versions)-int(secret.Metadata.MaxVersions):]
		}
	}

	// Loop through the versions and delete any that are older than DeleteVersionAfter
	// If DeleteVersionAfter is "0s", then there is no limit
	if mount.Config.Ttl != "0s" {
		for i, v := range versions {
			ttl, err := time.ParseDuration(mount.Config.Ttl)
			if err != nil {
				log.Println("failed to parse Ttl")
				log.Println(err)
			}
			deleteTime := v.Metadata.CreatedAt + int64(ttl.Seconds())
			if deleteTime >= now {
				versions = versions[i:]
				break
			}
		}
	}
	return versions
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

func getVersionsFromSecret(secret *shared.Secret, path string) []shared.SecretVersion {
	versions := []shared.SecretVersion{}

	for _, v := range secret.Paths {
		if v.Path == path {
			versions = v.Versions
		}
	}

	return versions
}

//
// exported functions
//

func GetKVConfig(c echo.Context) error {
	// get the metadata object of the secret
	// db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the path
	mount, key, _ := fullPathtoMountPath(c.Request().URL.String())

	// Check if the mount prefix is blocked
	for _, blocked := range blockedBuckets {
		if strings.HasPrefix(mount, blocked) {
			return c.JSON(http.StatusBadRequest, "Mount is blocked")
		}
	}

	// Check if the mount exists in the mounts bucket, and if it is a kv mount
	_, err := getMountConfig(mount)
	if err != nil {
		logger.Error("failed to get mount config", zap.String("key", mount))
		return c.JSON(http.StatusNotFound, err)
	}

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mount, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Put the secret metadata into the response object
	responseData := new(SecretMetadataResponse)
	responseData.Data = storedSecret.Metadata

	return c.JSON(http.StatusOK, responseData)
}

func ListMetadata(c echo.Context) error {
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mount, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	storedSecretString, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mount+"/"+key))
	}
	println("storedSecretString: ", string(storedSecretString))

	// Get the correct versions, either subpath or top level
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	versions := getVersionsFromSecret(storedSecret, path)

	// Build a response data object that contains a list of keys
	responseData := new(SecretMetadataListResponse)
	responseData.Data.CreatedAt = time.Unix(storedSecret.Metadata.CreatedAt, 0).UTC().Format(time.RFC3339)
	responseData.Data.CurrentVersion = versions[len(versions)-1].Metadata.Version
	responseData.Data.DeleteVersionAfter = storedSecret.Metadata.DeleteVersionAfter
	responseData.Data.MaxVersions = storedSecret.Metadata.MaxVersions
	responseData.Data.OldestVersion = versions[0].Metadata.Version
	responseData.Data.CustomMetadata = storedSecret.Metadata.CustomMetadata
	responseData.Data.Versions = make(map[string]VersionData)

	for _, v := range versions {
		tmpObj := new(VersionData)
		tmpObj.CreatedTime = time.Unix(v.Metadata.CreatedAt, 0).UTC().Format(time.RFC3339)
		if v.Metadata.DeletionTime == 0 {
			tmpObj.DeletedTime = ""
		} else {
			tmpObj.DeletedTime = time.Unix(v.Metadata.DeletionTime, 0).UTC().Format(time.RFC3339)
		}
		tmpObj.Destroyed = v.Metadata.Destroyed

		responseData.Data.Versions[strconv.FormatInt(v.Metadata.Version, 10)] = *tmpObj
	}

	return c.JSON(http.StatusOK, responseData)
}

func ListKeysforMount(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())

	// Build the requested path
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	// Check if the mount prefix is blocked
	for _, blocked := range blockedBuckets {
		if strings.HasPrefix(mount, blocked) {
			return c.JSON(http.StatusBadRequest, "Mount is blocked")
		}
	}

	// Check if the mount exists in the mounts bucket and if it is a kv mount
	_, err := getMountConfig(mount)
	if err != nil {
		logger.Error("failed to get mount config", zap.String("key", mount))
		return c.JSON(http.StatusNotFound, err)
	}

	// Get the value of the key
	secretEnc, err := db.ReadKey(mount, key, true)
	if err != nil {
		logger.Error("failed to read key", zap.String("key", mount))
		return c.JSON(http.StatusNotFound, err)
	}

	// Unmarshal the secret
	storedSecret := new(shared.Secret)
	err = json.Unmarshal([]byte(secretEnc), &storedSecret)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount))
		return c.JSON(http.StatusInternalServerError, err)
	}

	println("requested path: ", path)
	// requested path:  teststore2/test1
	//                 "teststore2/test1",
	//                 "teststore2/test1/sub1"
	//                 "teststore2/test1/sub1a",
	//                 "teststore2/test1/f1/f2/item1"
	paths := []string{}
	reqPathParts := strings.Split(path, "/")
	for _, v := range storedSecret.Paths {
		pathParts := strings.Split(v.Path, "/")
		if len(pathParts) <= len(reqPathParts)+1 && v.Path != path {
			iPath := strings.TrimPrefix(v.Path, path+"/")
			paths = append(paths, iPath)
		} else if v.Path != path {
			println("this is v: ", v.Path)
			joinedPath := strings.Join(pathParts[:len(reqPathParts)+1], "/")
			joinedPath = joinedPath + "/"
			iPath := strings.TrimPrefix(joinedPath, path+"/")
			paths = append(paths, iPath)
		}
	}

	// Build a response data object that contains a list of keys
	responseData := make(map[string]interface{})
	responseData["data"] = paths

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
	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())

	// Check if the mount prefix is blocked
	for _, blocked := range blockedBuckets {
		if strings.HasPrefix(mount, blocked) {
			return c.JSON(http.StatusBadRequest, "Mount is blocked")
		}
	}

	// Check if the mount exists in the mounts bucket and if it is a kv mount
	mountConfig, err := getMountConfig(mount)
	if err != nil {
		logger.Error("failed to get mount config", zap.String("key", mount))
		return c.JSON(http.StatusNotFound, err)
	}

	// Create a new secret
	storedSecret := new(shared.Secret)

	// Check if the key already exists
	secretStr, err := db.ReadKey(mount, key, true)
	if err != nil && err.Error() != "not found" {
		secretStr = ""
	}

	// If the key exists, unmarshal it
	if secretStr != "" {
		err = json.Unmarshal([]byte(secretStr), &storedSecret)
		if err != nil {
			logger.Error("failed to unmarshal secret", zap.String("key", mount))
			return c.JSON(http.StatusInternalServerError, err)
		}
	} else {
		storedSecret.Metadata.CreatedAt = time.Now().Unix()
		storedSecret.Metadata.Path = mount + "/" + key
		storedSecret.Metadata.MaxVersions = mountConfig.Config.MaxVersions
		storedSecret.Metadata.CustomMetadata = make(map[string]string)
		storedSecret.Paths = []shared.Paths{}
	}

	// Get the correct versions, either subpath or top level
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	versions := getVersionsFromSecret(storedSecret, path)

	// get the next version number
	// if the secret is new, then the version is 1
	// // if the secret exists, then the version is the current version + 1
	var v int64
	newSecret := false
	if len(versions) == 0 {
		v = 1
		newSecret = true
	} else {
		v = versions[len(versions)-1].Metadata.Version + 1
	}

	// // Create and add the new version
	secretVersion := new(shared.SecretVersion)
	secretVersion.Data = kv.Data
	secretVersion.Metadata.Version = int64(v)
	secretVersion.Metadata.CreatedAt = time.Now().Unix()
	secretVersion.Metadata.DeletionTime = 0
	secretVersion.Metadata.Destroyed = false
	secretVersion.Metadata.Deleted = false
	secretVersion.Metadata.CustomMetadata = make(map[string]string)
	versions = append(versions, *secretVersion)

	// Clean up the secret
	versions = cleanSecret(storedSecret, mountConfig, versions)

	// Add the new version to the secret
	// If the secret is new, then add the path and versions
	if newSecret {
		secretPath := new(shared.Paths)
		secretPath.Path = path
		secretPath.Versions = versions
		storedSecret.Paths = append(storedSecret.Paths, *secretPath)
	} else {
		for i, v := range storedSecret.Paths {
			if v.Path == path {
				println("Adding version to secret")
				storedSecret.Paths[i].Versions = versions
			}
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	println("updatedSecretStr: ", string(updatedSecretStr))
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mount, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return the secret
	responseData := new(GetSecretResponseData)
	responseData.Data = make(map[string]interface{})
	responseData.Data = secretVersion.Data
	responseData.Metadata.CreatedTime = time.Unix(secretVersion.Metadata.CreatedAt, 0).UTC().Format(time.RFC3339)
	responseData.Metadata.CustomMetadata = secretVersion.Metadata.CustomMetadata
	if secretVersion.Metadata.DeletionTime != 0 {
		responseData.Metadata.DeletionTime = time.Unix(secretVersion.Metadata.DeletionTime, 0).UTC().Format(time.RFC3339)
	} else {
		responseData.Metadata.DeletionTime = ""
	}
	responseData.Metadata.Destroyed = secretVersion.Metadata.Destroyed
	responseData.Metadata.Version = secretVersion.Metadata.Version
	fullResponseData := new(GetSecretResponse)
	fullResponseData.Data = *responseData
	return c.JSON(http.StatusOK, fullResponseData)
}

func GetKV(c echo.Context) error {
	// db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())
	// Get the request parameters
	version := c.QueryParam("version")

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mount, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Get the correct versions, either subpath or top level
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	versions := getVersionsFromSecret(storedSecret, path)

	// Return the secret
	// Get the index of the latest version and build the response
	var getVersion int64
	if version != "" {
		getVersion, err = strconv.ParseInt(version, 10, 64)
		if err != nil {
			logger.Error("failed to parse version", zap.String("key", mount+"/"+key))
			return c.JSON(http.StatusInternalServerError, err)
		}
	} else {
		// If no version is specified, return the latest version that is not deleted
		getVersion = 0
		for _, v := range versions {
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
	for _, v := range versions {
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
	println("DeleteKV")
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mount, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Get the correct versions, either subpath or top level
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	versions := getVersionsFromSecret(storedSecret, path)

	// Check if method is delete
	deleteSecret := new(PostedDeleteSecret)
	if c.Request().Method == "DELETE" {
		deleteSecret.Versions = append(deleteSecret.Versions, versions[len(versions)-1].Metadata.Version)
	} else {
		// Validate the input
		if err := c.Bind(deleteSecret); err != nil {
			logger.Error("failed to bind request body", zap.Error(err))
			return c.JSON(http.StatusBadRequest, err)
		}
	}

	// Mark the versions as deleted
	for _, v := range deleteSecret.Versions {
		for i, sv := range versions {
			if sv.Metadata.Version == v {
				versions[i].Metadata.Deleted = true
				versions[i].Metadata.DeletionTime = time.Now().Unix()
			}
		}
	}

	// Update the versions in the secret
	for i, v := range storedSecret.Paths {
		if v.Path == path {
			storedSecret.Paths[i].Versions = versions
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mount, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return blank updated
	return c.JSON(http.StatusNoContent, "")

}

func UndeleteKV(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mount, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Validate the input
	deleteSecret := new(PostedDeleteSecret)
	if err := c.Bind(deleteSecret); err != nil {
		logger.Error("failed to bind request body", zap.Error(err))
		return c.JSON(http.StatusBadRequest, err)
	}

	// Get the correct versions, either subpath or top level
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	versions := getVersionsFromSecret(storedSecret, path)

	// Set deleted to false for the versions and set the deletion time to 0
	for _, v := range deleteSecret.Versions {
		for i, sv := range versions {
			if sv.Metadata.Version == v {
				versions[i].Metadata.Deleted = false
				versions[i].Metadata.DeletionTime = 0
			}
		}
	}

	// Update the versions in the secret
	for i, v := range storedSecret.Paths {
		if v.Path == path {
			storedSecret.Paths[i].Versions = versions
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mount, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return blank updated
	return c.JSON(http.StatusNoContent, "")
}

func DestroyKV(c echo.Context) error {
	db := storage.GetStore()
	logger := c.Get("logger").(*zap.Logger)

	// Get the mount mountNoSlash and key
	mount, key, subpath := fullPathtoMountPath(c.Request().URL.String())

	// Get and unmarshal the secret
	storedSecret, err := getUnmarshalSecret(mount, key)
	if err != nil {
		logger.Error("failed to unmarshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Validate the input
	deleteSecret := new(PostedDeleteSecret)
	if err := c.Bind(deleteSecret); err != nil {
		logger.Error("failed to bind request body", zap.Error(err))
		return c.JSON(http.StatusBadRequest, err)
	}

	// Get the correct versions, either subpath or top level
	path := ""
	if subpath != "" {
		path = mount + "/" + key + "/" + subpath
	} else {
		path = mount + "/" + key
	}

	versions := getVersionsFromSecret(storedSecret, path)

	// Set destroyed to true for the versions, set the deletion time, and remove the data
	for _, v := range deleteSecret.Versions {
		for i, sv := range versions {
			if sv.Metadata.Version == v {
				versions[i].Metadata.Destroyed = true
				versions[i].Metadata.DeletionTime = time.Now().Unix()
				versions[i].Data = nil
			}
		}
	}

	// Update the versions in the secret
	for i, v := range storedSecret.Paths {
		if v.Path == path {
			storedSecret.Paths[i].Versions = versions
		}
	}

	// Encrypt and store the secret
	updatedSecretStr, err := json.Marshal(storedSecret)
	if err != nil {
		logger.Error("failed to marshal secret", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = db.CreateKey(mount, key, string(updatedSecretStr), true)
	if err != nil {
		logger.Error("failed to create key", zap.String("key", mount+"/"+key))
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Return blank updated
	return c.JSON(http.StatusNoContent, "")
}
