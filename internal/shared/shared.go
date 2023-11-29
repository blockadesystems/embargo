/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package shared

import "github.com/google/uuid"

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
