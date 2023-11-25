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
	"github.com/boltdb/bolt"
	"github.com/gocql/gocql"
	"github.com/google/uuid"
)

var Store Storage
var Keyspace string

type EncryptedSecret struct {
	Data  []byte
	KeyId uuid.UUID
}

func InitDB(dbType string) {
	var err error

	switch dbType {
	case "memory":
		println("Using memory storage")
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
		Store = CassandraStorage{}
		Store, err = Store.OpenDB()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		Store.CreateBucket("embargo_mounts")
		Store.CreateBucket("embargo_sys")
		Store.CreateBucket("embargo_tokens")
		Store.CreateBucket("embargo_policies")
	}
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
	GetMountChildren(bucket string) ([]string, error)
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
	b.Db, err = bolt.Open("srevault.db", 0600, nil)
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

func (b BoltStorage) GetMountChildren(bucket string) ([]string, error) {
	var children []string
	err := b.Db.View(func(tx *bolt.Tx) error {
		mounts_bucket := tx.Bucket([]byte("embargo_mounts"))

		c := mounts_bucket.Cursor()
		// search the mounts_bucket for items with a parent = bucket
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// marshal the json into a Mounts struct
			// check if the parent is the bucket
			// if so, append the path to the children slice
			// return the children slice

			thisMount := shared.Mounts{}
			err := json.Unmarshal(v, &thisMount)
			if err != nil {
				println(err)
			}
			if thisMount.Parent == bucket {
				children = append(children, thisMount.Path+"/")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return children, nil
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

func (c CassandraStorage) GetMountChildren(bucket string) ([]string, error) {
	var children []string

	data := c.Db.Query("SELECT value FROM " + Keyspace + ".embargo_mounts").Iter()
	var value string
	for data.Scan(&value) {
		thisMount := shared.Mounts{}
		err := json.Unmarshal([]byte(value), &thisMount)
		if err != nil {
			println(err)
		}
		if thisMount.Parent == bucket {
			// remove the bucket from the path
			// append the path to the children slice
			child := strings.Replace(thisMount.Path, bucket, "", 1)
			// remove leading slash
			child = strings.TrimPrefix(child, "/")
			children = append(children, child+"/")
		}
	}

	return children, nil
}
