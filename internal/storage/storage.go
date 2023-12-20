/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blockadesystems/embargo/internal/encryption"
	"github.com/blockadesystems/embargo/internal/shared"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Store Storage
var Keyspace string

type EncryptedSecret struct {
	Data  []byte
	KeyId uuid.UUID
}

func InitDB(dbType string) {
	println("Initializing database")
	var err error

	switch dbType {
	case "memory":
		Store = BoltStorage{}
		Store, err = Store.OpenDB()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		Store.CreateBucket("embargo_mounts")
		Store.CreateBucket("embargo_sys")
		Store.CreateBucket("embargo_tokens")
		Store.CreateBucket("embargo_policies")
	case "cassandra":
		println("Initializing Cassandra")
		Store = CassandraStorage{}
		Store, err = Store.OpenDB()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		println("Creating buckets")
		Store.CreateBucket("embargo_mounts")
		Store.CreateBucket("embargo_sys")
		Store.CreateBucket("embargo_tokens")
		Store.CreateBucket("embargo_policies")
		println("Buckets created")
	case "postgres":
		println("Initializing Postgres")
		Store = PostgresStorage{}
		Store, err = Store.OpenDB()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		println("Creating buckets")
		Store.CreateBucket("embargo_mounts")
		Store.CreateBucket("embargo_sys")
		Store.CreateBucket("embargo_tokens")
		Store.CreateBucket("embargo_policies")
		println("Buckets created")
	}

	// Add sys, tokens, and policies mounts if they don't exist
	sysMount := shared.Mounts{
		Path:        "sys",
		BucketType:  "sys",
		Description: "System mount",
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Config:      shared.MountConfig{},
	}
	sysMountJSON, err := json.Marshal(sysMount)
	if err != nil {
		println("error marshalling sys mount")
		fmt.Println(err)
		os.Exit(1)
	}
	// check if sys mount exists in mounts bucket
	sysMnt, _ := Store.ReadKey("embargo_mounts", "sys", false)
	if sysMnt == "" {
		Store.CreateKey("embargo_mounts", "sys", string(sysMountJSON), false)
	}
	println("sys mount created")

	tokensMount := shared.Mounts{
		Path:        "tokens",
		BucketType:  "tokens",
		Description: "Tokens mount",
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Config:      shared.MountConfig{},
	}
	tokensMountJSON, err := json.Marshal(tokensMount)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// check if tokens mount exists in mounts bucket
	tokensMnt, _ := Store.ReadKey("embargo_mounts", "tokens", false)

	if tokensMnt == "" {
		Store.CreateKey("embargo_mounts", "tokens", string(tokensMountJSON), false)
	}
	println("tokens mount created")

	policiesMount := shared.Mounts{
		Path:        "policies",
		BucketType:  "policies",
		Description: "Policies mount",
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Config:      shared.MountConfig{},
	}
	policiesMountJSON, err := json.Marshal(policiesMount)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// check if policies mount exists in mounts bucket
	policiesMnt, _ := Store.ReadKey("embargo_mounts", "policies", false)

	if policiesMnt == "" {
		Store.CreateKey("embargo_mounts", "policies", string(policiesMountJSON), false)
	}
	println("policies mount created")

	println("Database initialized")

}

func GetStore() Storage {
	return Store
}

// Create an abstraction layer for the bolt database
// Create a bolt database
// Create a bolt bucket
// Create a bolt key/value pair
// Read a bolt key/value pair
// Update a bolt key/value pair
// Delete a bolt key/value pair
// Delete a bolt bucket

type Storage interface {
	OpenDB() (Storage, error)
	CreateBucket(bucket string) error
	CreateKey(bucket string, key string, value string, encrypt bool) error
	ReadKey(bucket string, key string, encrypted bool) (string, error)
	ReadAllKeys(bucket string) (map[string]string, error)
	UpdateKey(bucket string, key string, value string) error
	DeleteKey(bucket string, key string) error
	DeleteBucket(bucket string) error
	BucketExists(bucket string) bool
	// GetMountChildren(bucket string, key string) ([]string, error)
}

type BoltStorage struct {
	Db *bolt.DB
}

type CassandraStorage struct {
	Db *gocql.Session
}

func encryptSecret(value string) string {
	e := EncryptedSecret{}
	e.KeyId = encryption.EncKeys.ActiveKey.Id

	// encrypt value
	encryptedValue, err := encryption.EncryptSecret(value)
	if err != nil {
		return ""
	}
	e.Data = encryptedValue
	encryptedObj, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	value = string(encryptedObj)
	return value
}

func decryptSecret(value string) string {
	rawObj := EncryptedSecret{}
	err := json.Unmarshal([]byte(value), &rawObj)
	if err != nil {
		return ""
	}

	encryptionKeyId := rawObj.KeyId

	decryptedValue, err := encryption.DecryptSecret(rawObj.Data, encryptionKeyId)
	if err != nil {
		return ""
	}
	value = decryptedValue
	return value
}

func (b BoltStorage) OpenDB() (Storage, error) {
	var err error
	embargoFile := os.Getenv("EMBARGO_FILE")
	if embargoFile == "" {
		embargoFile = "embargo.db"
	}
	b.Db, err = bolt.Open(embargoFile, 0600, nil)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (b BoltStorage) CreateBucket(bucket string) error {
	err := b.Db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (b BoltStorage) CreateKey(bucket string, key string, value string, encrypt bool) error {

	if encrypt {
		value = encryptSecret(value)
	}

	err := b.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		// catch panic here if bucket doesn't exist
		if b == nil {
			return fmt.Errorf("bucket does not exist")
		}
		err := b.Put([]byte(key), []byte(value))
		if err != nil {
			return fmt.Errorf("create key: %s", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (b BoltStorage) ReadAllKeys(bucket string) (map[string]string, error) {
	keys := make(map[string]string)
	err := b.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		// catch panic here if bucket doesn't exist
		if b == nil {
			return fmt.Errorf("bucket does not exist")
		}
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			keys[string(k)] = string(v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (b BoltStorage) ReadKey(bucket string, key string, encrypted bool) (string, error) {
	var value string
	err := b.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		// catch panic here if bucket doesn't exist
		if b == nil {
			return fmt.Errorf("bucket does not exist")
		}
		v := b.Get([]byte(key))
		value = string(v)
		return nil
	})
	if err != nil {
		return "", err
	}

	if encrypted {
		value = decryptSecret(value)
	}

	return value, nil
}

func (b BoltStorage) UpdateKey(bucket string, key string, value string) error {
	err := b.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		// catch panic here if bucket doesn't exist
		if b == nil {
			return fmt.Errorf("bucket does not exist")
		}
		err := b.Put([]byte(key), []byte(value))
		if err != nil {
			return fmt.Errorf("update key: %s", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (b BoltStorage) DeleteKey(bucket string, key string) error {
	err := b.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		// catch panic here if bucket doesn't exist
		if b == nil {
			return fmt.Errorf("bucket does not exist")
		}
		err := b.Delete([]byte(key))
		if err != nil {
			return fmt.Errorf("delete key: %s", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (b BoltStorage) DeleteBucket(bucket string) error {
	err := b.Db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(bucket))
		if err != nil {
			return fmt.Errorf("delete bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (b BoltStorage) BucketExists(bucket string) bool {
	var exists bool
	err := b.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			exists = false
		} else {
			exists = true
		}
		return nil
	})
	if err != nil {
		return false
	}
	return exists
}

// Cassandra
func (c CassandraStorage) OpenDB() (Storage, error) {
	var err error
	// Get Cassandra hosts from environment
	cassandraHost := os.Getenv("EMBARGO_CASSANDRA_HOSTS")
	if cassandraHost == "" {
		panic("EMBARGO_CASSANDRA_HOSTS environment variable not set")
	}

	// Get Cassandra username from environment
	cassandraUsername := os.Getenv("EMBARGO_CASSANDRA_USERNAME")
	if cassandraUsername == "" {
		panic("EMBARGO_CASSANDRA_USERNAME environment variable not set")
	}

	// Get Cassandra password from environment
	cassandraPassword := os.Getenv("EMBARGO_CASSANDRA_PASSWORD")
	if cassandraPassword == "" {
		panic("EMBARGO_CASSANDRA_PASSWORD environment variable not set")
	}

	// Split hosts into slice
	cassandraHosts := strings.Split(cassandraHost, ",")

	cluster := gocql.NewCluster(cassandraHosts...)
	// cluster.Consistency = gocql.Quorum
	cluster.ProtoVersion = 4
	cluster.ConnectTimeout = time.Second * 10
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username:              cassandraUsername,
		Password:              cassandraPassword,
		AllowedAuthenticators: []string{"com.instaclustr.cassandra.auth.InstaclustrPasswordAuthenticator"},
	}
	c.Db, err = cluster.CreateSession()
	if err != nil {
		return nil, err
	}

	// Get the keyspace from the environment or set default
	keyspace := os.Getenv("EMBARGO_CASSANDRA_KEYSPACE")
	if keyspace == "" {
		keyspace = "embargo"
	}
	Keyspace = keyspace

	// Create keyspace if it doesn't exist
	err = c.Db.Query("CREATE KEYSPACE IF NOT EXISTS " + Keyspace + " WITH REPLICATION = { 'class' : 'NetworkTopologyStrategy', 'datacenter1' : 1 };").Exec()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c CassandraStorage) CreateBucket(bucket string) error {
	err := c.Db.Query("CREATE TABLE IF NOT EXISTS " + Keyspace + "." + bucket +
		" (key text PRIMARY KEY, value blob);").Exec()
	if err != nil {
		return err
	}

	return nil
}

func (c CassandraStorage) CreateKey(bucket string, key string, value string, encrypt bool) error {
	if encrypt {
		value = encryptSecret(value)
	}
	err := c.Db.Query("INSERT INTO "+Keyspace+"."+bucket+" (key, value) VALUES (?, ?)", key, value).Exec()
	if err != nil {
		println("error inserting key")
		return err
	}

	return nil
}

func (c CassandraStorage) ReadAllKeys(bucket string) (map[string]string, error) {
	keys := make(map[string]string)

	data := c.Db.Query("SELECT * FROM " + Keyspace + "." + bucket).Iter()
	var key string
	var value string
	for data.Scan(&key, &value) {
		keys[key] = value
	}

	return keys, nil
}

func (c CassandraStorage) ReadKey(bucket string, key string, encrypted bool) (string, error) {
	var value string
	err := c.Db.Query("SELECT value FROM "+Keyspace+"."+bucket+" WHERE key = ?", key).Scan(&value)
	if err != nil {
		return "", err
	}

	if encrypted {
		value = decryptSecret(value)
	}

	return value, nil
}

func (c CassandraStorage) UpdateKey(bucket string, key string, value string) error {
	err := c.Db.Query("UPDATE "+Keyspace+"."+bucket+" SET value = ? WHERE key = ?", value, key).Exec()
	if err != nil {
		return err
	}
	return nil
}

func (c CassandraStorage) DeleteKey(bucket string, key string) error {
	err := c.Db.Query("DELETE FROM "+Keyspace+"."+bucket+" WHERE key = ?", key).Exec()
	if err != nil {
		return err
	}
	return nil
}

func (c CassandraStorage) DeleteBucket(bucket string) error {
	err := c.Db.Query("DROP TABLE " + Keyspace + "." + bucket).Exec()
	if err != nil {
		return err
	}
	return nil
}

func (c CassandraStorage) BucketExists(bucket string) bool {
	var exists bool
	err := c.Db.Query("SELECT * FROM system_schema.tables WHERE keyspace_name = ? AND table_name = ?", Keyspace, bucket).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// Postgres
type PostgresStorage struct {
	Db *gorm.DB
}

func (p PostgresStorage) OpenDB() (Storage, error) {
	var err error
	// Get Postgres host from environment
	postgresHost := os.Getenv("EMBARGO_POSTGRES_HOST")
	if postgresHost == "" {
		panic("EMBARGO_POSTGRES_HOST environment variable not set")
	}

	// Get Postgres username from environment
	postgresUsername := os.Getenv("EMBARGO_POSTGRES_USERNAME")
	if postgresUsername == "" {
		panic("EMBARGO_POSTGRES_USERNAME environment variable not set")
	}

	// Get Postgres password from environment
	postgresPassword := os.Getenv("EMBARGO_POSTGRES_PASSWORD")
	if postgresPassword == "" {
		panic("EMBARGO_POSTGRES_PASSWORD environment variable not set")
	}

	// Get Postgres port from environment
	postgresPort := os.Getenv("EMBARGO_POSTGRES_PORT")
	if postgresPort == "" {
		postgresPort = "5432"
	}

	// Get Postgres database from environment
	postgresDatabase := os.Getenv("EMBARGO_POSTGRES_DATABASE")
	if postgresDatabase == "" {
		postgresDatabase = "embargo"
	}

	dsn := "host=" + postgresHost + " user=" + postgresUsername + " password=" + postgresPassword + " dbname=" + postgresDatabase + " port=" + postgresPort + " sslmode=disable TimeZone=UTC"
	p.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p PostgresStorage) CreateBucket(bucket string) error {
	err := p.Db.Exec("CREATE TABLE IF NOT EXISTS " + bucket +
		" (key text PRIMARY KEY, value text);").Error
	if err != nil {
		return err
	}

	return nil
}

func (p PostgresStorage) CreateKey(bucket string, key string, value string, encrypt bool) error {
	if encrypt {
		value = encryptSecret(value)
	}
	err := p.Db.Exec("INSERT INTO "+bucket+" (key, value) VALUES (?, ?)", key, value).Error
	if err != nil {
		println("error inserting key")
		return err
	}

	return nil
}

func (p PostgresStorage) ReadAllKeys(bucket string) (map[string]string, error) {
	keys := make(map[string]string)

	data := p.Db.Raw("SELECT * FROM " + bucket).Find(&keys)
	if data.Error != nil {
		return nil, data.Error
	}

	return keys, nil
}

func (p PostgresStorage) ReadKey(bucket string, key string, encrypted bool) (string, error) {
	var value string
	data := p.Db.Raw("SELECT value FROM "+bucket+" WHERE key = ?", key).Scan(&value)
	if data.Error != nil {
		return "", data.Error
	}

	if encrypted {
		value = decryptSecret(value)
	}

	return value, nil
}

func (p PostgresStorage) UpdateKey(bucket string, key string, value string) error {
	err := p.Db.Exec("UPDATE "+bucket+" SET value = ? WHERE key = ?", value, key).Error
	if err != nil {
		return err
	}
	return nil
}

func (p PostgresStorage) DeleteKey(bucket string, key string) error {
	err := p.Db.Exec("DELETE FROM "+bucket+" WHERE key = ?", key).Error
	if err != nil {
		return err
	}
	return nil
}

func (p PostgresStorage) DeleteBucket(bucket string) error {
	err := p.Db.Exec("DROP TABLE " + bucket).Error
	if err != nil {
		return err
	}
	return nil
}

func (p PostgresStorage) BucketExists(bucket string) bool {
	var exists bool
	data := p.Db.Raw("SELECT * FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ?", bucket).Scan(&exists)
	if data.Error != nil {
		return false
	}
	return exists
}
