/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package shared

import (
	"github.com/blockadesystems/embargo/internal/raft"
	"github.com/google/uuid"
)

type UnsealData struct {
	Threshold int
	Shares    int
	Keys      []string
}

type Mounts struct {
	Path        string `json:"path"`
	BucketType  string `json:"type"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
	Config      MountConfig
}

type MountConfig struct {
	Ttl         string `json:"ttl"`
	MaxVersions int64  `json:"max_versions"`
}

type EncryptionKey struct {
	Id           uuid.UUID `json:"id"`
	Key          string    `json:"key"`
	CreatedAt    int64     `json:"created_at"`
	DeprecatedAt int64     `json:"deprecated_at"`
}

type EncryptionKeyList struct {
	ActiveKey EncryptionKey   `json:"active_key"`
	OldKeys   []EncryptionKey `json:"keys"`
}

type SecretMetadata struct {
	CreatedAt          int64             `json:"created_at" validate:"required"`
	Path               string            `json:"path" validate:"required"`
	MaxVersions        int64             `json:"max_versions" validate:"required"`
	DeleteVersionAfter int64             `json:"delete_version_after" validate:"required"`
	CustomMetadata     map[string]string `json:"custom_metadata" validate:"required"`
}

type SecretVersionMetadata struct {
	Version        int64             `json:"version" validate:"required"`
	CreatedAt      int64             `json:"created_at" validate:"required"`
	DeletionTime   int64             `json:"deletion_time" validate:"required"`
	Destroyed      bool              `json:"destroyed" validate:"required"`
	Deleted        bool              `json:"deleted" validate:"required"`
	CustomMetadata map[string]string `json:"custom_metadata" validate:"required"`
}

type SecretVersion struct {
	Data     interface{}           `json:"data" validate:"required"`
	Metadata SecretVersionMetadata `json:"metadata" validate:"required"`
}

type Paths struct {
	Path     string          `json:"path"`
	Versions []SecretVersion `json:"versions"`
}

type Secret struct {
	Metadata SecretMetadata `json:"metadata" validate:"required"`
	Paths    []Paths        `json:"paths" validate:"required"`
}

type InitSysRequest struct {
	Threshold int `json:"threshold"`
	Shares    int `json:"shares"`
}

type InitSysResponse struct {
	Shares    []string `json:"shares"`
	RootToken string   `json:"root_token"`
}

type KvResponse struct {
	Data KvResponseData `json:"data" validate:"required"`
}

type KvResponseData struct {
	Data     interface{} `json:"data" validate:"required"`
	Metadata struct {
		CreatedTime    string            `json:"created_time" validate:"required"`
		CustomMetadata map[string]string `json:"custom_metadata" validate:"required"`
		DeletionTime   string            `json:"deletion_time" validate:"required"`
		Destroyed      bool              `json:"destroyed" validate:"required"`
		Version        int64             `json:"version" validate:"required"`
	} `json:"metadata" validate:"required"`
}

type Storage interface {
	OpenDB() (Storage, error)
	CreateBucket(bucket string) error
	CreateKey(bucket string, key string, value string, encrypt bool) error
	ReadKey(bucket string, key string, encrypted bool) (string, error)
	ReadAllKeys(bucket string) (map[string]string, error)
	UpdateKey(bucket string, key string, value string, encrypt bool) error
	DeleteKey(bucket string, key string) error
	DeleteBucket(bucket string) error
	BucketExists(bucket string) bool
}

var Unseal UnsealData

var StorageType string
var Store Storage

func GetStore() Storage {
	return Store
}

var RaftStore *raft.Store
var RaftNodeId string

func IsRaftLeader() bool {
	_, leaderId := RaftStore.Raft.LeaderWithID()
	return string(leaderId) == RaftNodeId
}

var RaftJoinRequest struct {
	Address       string `json:"address"`
	SkipTlsVerify bool   `json:"skip_tls_verify"`
}

type RaftClusterRequest struct {
	NodeSecretString string `json:"node_secret_string"`
	NodeId           string `json:"node_id"`
	RaftAddress      string `json:"raft_address"`
}

var RaftClusterRequestData []RaftClusterRequest
