/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package storage

import (
	"bytes"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blockadesystems/embargo/internal/encryption"
	"github.com/blockadesystems/embargo/internal/raft"
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
		shared.StorageType = "memory"
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
		shared.StorageType = "cassandra"
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
		shared.StorageType = "postgres"
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
	case "raft":
		shared.StorageType = "raft"
		println("Initializing Raft")
		Store = RaftStorage{}
		Store, err = Store.OpenDB()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		_, leaderId := shared.RaftStore.Raft.LeaderWithID()
		nodeId := os.Getenv("EMBARGO_RAFT_NODE_ID")
		println("Leader ID: " + leaderId)
		println("Node ID: " + nodeId)

		if string(leaderId) == nodeId {
			println("Node is leader")
			println(string(leaderId))
			println("Creating buckets")
			// Store.CreateBucket("embargo_mounts")
			// Store.CreateBucket("embargo_sys")
			// Store.CreateBucket("embargo_tokens")
			// Store.CreateBucket("embargo_policies")
			println("Buckets created")
		} else {
			println("Node is not leader, not creating buckets")

		}

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
	UpdateKey(bucket string, key string, value string, encrypt bool) error
	DeleteKey(bucket string, key string) error
	DeleteBucket(bucket string) error
	BucketExists(bucket string) bool
}

type BoltStorage struct {
	Db *bolt.DB
}

type CassandraStorage struct {
	Db *gocql.Session
}

type RaftStorage struct {
	Db *raft.Store
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

func (b BoltStorage) UpdateKey(bucket string, key string, value string, encrypt bool) error {
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

func (c CassandraStorage) UpdateKey(bucket string, key string, value string, encrypt bool) error {
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

	// dsn := "host=" + postgresHost + " user=" + postgresUsername + " password=" + postgresPassword + " dbname=" + postgresDatabase + " port=" + postgresPort + " sslmode=disable TimeZone=UTC"
	dsn := "host=" + postgresHost + " user=" + postgresUsername + " password=" + postgresPassword + " port=" + postgresPort + " dbname=" + postgresDatabase + " sslmode=disable TimeZone=UTC options='--client_encoding=UTF8'"
	p.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Create database if it doesn't exist
	// err = p.Db.Exec("SELECT 'CREATE DATABASE' " + postgresDatabase + " WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '" + postgresDatabase + "')").Error
	// if err != nil {
	// 	return nil, err
	// }

	return p, nil
}

func (p PostgresStorage) CreateBucket(bucket string) error {
	// create table as hstore if it doesn't exist

	err := p.Db.Exec("CREATE TABLE IF NOT EXISTS " + bucket +
		" (key text PRIMARY KEY, value bytea);").Error
	if err != nil {
		return err
	}

	return nil
}

func (p PostgresStorage) CreateKey(bucket string, key string, value string, encrypt bool) error {
	println("creating key")
	println(bucket)
	println(key)
	println(value)
	if encrypt {
		value = encryptSecret(value)
	}

	valueUTF := []byte(value)

	err := p.Db.Exec("INSERT INTO "+bucket+" (key, value) VALUES (?, ?)", key, valueUTF).Error
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

	// convert bytea to string
	valueSt := string(value[:])

	if encrypted {
		// value = decryptSecret(value)
		valueSt = decryptSecret(valueSt)
	}

	// return value, nil
	return valueSt, nil
}

func (p PostgresStorage) UpdateKey(bucket string, key string, value string, encrypt bool) error {
	if encrypt {
		value = encryptSecret(value)
	}

	valueUTF := []byte(value)

	err := p.Db.Exec("UPDATE "+bucket+" SET value = ? WHERE key = ?", valueUTF, key).Error
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

// Raft

func (r RaftStorage) OpenDB() (Storage, error) {
	r.Db = raft.New(false)

	bindAddr := os.Getenv("EMBARGO_RAFT_ADDRESS")
	if bindAddr == "" {
		bindAddr = ":8081"
	}
	r.Db.RaftBind = bindAddr

	raftDir := os.Getenv("EMBARGO_RAFT_DIR")
	if raftDir == "" {
		raftDir = "raft"
	}

	r.Db.RaftDir = raftDir

	nodeID := os.Getenv("EMBARGO_RAFT_NODE_ID")
	if nodeID == "" {
		nodeID = "node1"
	}
	joinAddrsStr := os.Getenv("EMBARGO_RAFT_JOIN_ADDRESSES")

	r.Db.Open(joinAddrsStr == "", nodeID)
	// r.Db.Open(true, nodeID)

	// if joinAddrsStr != "" {
	// 	log.Println("Joining raft cluster")
	// 	joinAddrs := strings.Split(joinAddrsStr, ",")
	// 	for _, addr := range joinAddrs {
	// 		log.Println("Joining " + addr)
	// 		addrSplit := strings.Split(addr, "-")
	// 		nodeId := addrSplit[0]
	// 		nodeAddr := addrSplit[1]
	// 		// r.Db.Join(addrSplit[0], addrSplit[1])
	// 		r.Db.Join(nodeId, nodeAddr)
	// 	}
	// }

	// sleep for 5 seconds to give the raft cluster time to form
	time.Sleep(5 * time.Second)

	// check if this node is the leader, if not issue join command if joinAddrsStr is set
	_, leaderId := r.Db.Raft.LeaderWithID()
	if string(leaderId) != nodeID {
		if joinAddrsStr != "" {
			log.Println("Joining raft cluster")
			joinAddrs := strings.Split(joinAddrsStr, ",")
			for _, addr := range joinAddrs {
				log.Println("Joining " + addr)
				addrSplit := strings.Split(addr, "-")
				// nodeId := addrSplit[0]
				nodeAddr := addrSplit[1]
				b, err := json.Marshal(map[string]string{"node_addr": bindAddr, "node_id": nodeID})
				if err != nil {
					log.Println("error marshalling json")
					log.Println(err)
				}
				transCfg := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
				}
				client := &http.Client{Transport: transCfg}
				resp, err := client.Post("https://"+nodeAddr+"/raft/join", "application/json", bytes.NewBuffer(b))
				if err != nil {
					log.Println("error joining raft cluster")
					log.Println(err)
				}
				defer resp.Body.Close()
				htmlData, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Println("error reading response body")
					log.Println(err)
				}
				log.Println(string(htmlData))
			}
		}
	}

	shared.RaftStore = r.Db
	shared.RaftNodeId = nodeID

	return r, nil
}

func (r RaftStorage) CreateBucket(bucket string) error {
	// Check if key (aka bucket) exists
	// If it doesn't exist, create it
	b, err := r.Db.Get(bucket)
	if err != nil {
		log.Println("error getting bucket")
		log.Println(err)
		return err
	}
	if b == "{}" || b == "" {
		err = r.Db.Set(bucket, "{}")
		if err != nil {
			log.Println("error setting bucket")
			log.Println(err)
			return err
		}
	}
	return nil
}

func (r RaftStorage) CreateKey(bucket string, key string, value string, encrypt bool) error {
	// log.Println("starting create key")
	// log.Println("bucket: " + bucket)
	// log.Println("key: " + key)

	if encrypt {
		value = encryptSecret(value)
	}

	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		return err
	}

	// if the bucket doesn't exist, create it
	if b == "" {
		err = r.Db.Set(bucket, "{}")
		if err != nil {
			log.Println("error setting bucket")
			return err
		}
	}

	// get the bucket again
	b, err = r.Db.Get(bucket)
	if err != nil {
		log.Println("error getting bucket")
		return err
	}

	// if the bucket still doesn't exist, return an error
	if b == "" {
		log.Println("bucket does not exist after creating it")
		return fmt.Errorf("can not create key, bucket does not exist")
	}

	// unmashal the bucket into a struct
	bucketStruct := make(map[string]string)
	err = json.Unmarshal([]byte(b), &bucketStruct)
	if err != nil {
		return err
	}

	// add or update the key/value pair
	valueB64 := b64.StdEncoding.EncodeToString([]byte(value))
	bucketStruct[key] = valueB64

	// Marshal the bucket back to JSON
	bucketValueJSON, err := json.Marshal(bucketStruct)
	if err != nil {
		log.Println("error marshalling bucket")
		return err
	}

	// Set the bucket's value
	err = r.Db.Set(bucket, string(bucketValueJSON))
	if err != nil {
		log.Println("error setting bucket")
		return err
	}

	// testing
	b, err = r.Db.Get(bucket)
	if err != nil {
		return err
	}
	log.Println("bucket: " + b)

	return nil

}

func (r RaftStorage) ReadAllKeys(bucket string) (map[string]string, error) {
	// log.Println("starting read all keys")
	keys := make(map[string]string)

	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		return nil, err
	}

	// if the bucket doesn't exist, return an error
	if b == "" {
		return nil, fmt.Errorf("bucket does not exist")
	}

	// unmashal the bucket into a struct
	bucketStruct := make(map[string]string)
	err = json.Unmarshal([]byte(b), &bucketStruct)
	if err != nil {
		return nil, err
	}

	// loop through the keys and add them to the map
	for k, v := range bucketStruct {
		keys[k] = v
	}

	return keys, nil
}

func (r RaftStorage) ReadKey(bucket string, key string, encrypted bool) (string, error) {
	var value string
	// log.Println("starting read key")
	// log.Println("bucket: " + bucket)
	// log.Println("key: " + key)

	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		log.Println("error getting bucket")
		return "", err
	}

	// if the bucket doesn't exist, return an error
	if b == "" {
		log.Printf("bucket %s does not exist", bucket)
		return "", fmt.Errorf("bucket does not exist")
	}

	// unmashal the bucket into a struct
	bucketStruct := make(map[string]string)
	err = json.Unmarshal([]byte(b), &bucketStruct)
	if err != nil {
		return "", err
	}

	// try to find the key in the bucket
	for k, v := range bucketStruct {
		if k == key {
			log.Println("found key")
			log.Println(v)
			value = v
		}
	}

	if value == "" {
		log.Println("key not found")
		log.Println("key: " + key)
		log.Println("bucket: " + bucket)
		log.Println("value: " + value)
		return "", fmt.Errorf("key does not exist")
	}

	// decode the value
	valueDecoded, err := b64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	value = string(valueDecoded)

	// if the key doesn't exist, return an error
	if value == "" {
		return "", fmt.Errorf("key does not exist")
	}

	if encrypted {
		value = decryptSecret(string(value))
	}

	return value, nil
}

func (r RaftStorage) UpdateKey(bucket string, key string, value string, encrypt bool) error {
	// log.Println("starting update key")
	// log.Println("bucket: " + bucket)
	// log.Println("key: " + key)
	// log.Println("value: " + value)
	if encrypt {
		value = encryptSecret(value)
	}

	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		log.Println("error getting bucket")
		return err
	}

	// if the bucket doesn't exist, return an error
	if b == "" {
		log.Printf("bucket %s does not exist", bucket)
		return fmt.Errorf("bucket does not exist")
	}

	// unmashal the bucket into a struct
	bucketStruct := make(map[string]string)
	err = json.Unmarshal([]byte(b), &bucketStruct)
	if err != nil {
		log.Println("error unmarshalling bucket")
		return err
	}

	// set the key/value pair
	valueB64 := b64.StdEncoding.EncodeToString([]byte(value))
	bucketStruct[key] = valueB64

	// Marshal the bucket back to JSON
	bucketValueJSON, err := json.Marshal(bucketStruct)
	if err != nil {
		log.Println("error marshalling bucket")
		return err
	}

	// Set the bucket's value
	err = r.Db.Set(bucket, string(bucketValueJSON))
	if err != nil {
		log.Println("error setting bucket")
		return err
	}

	return nil
}

func (r RaftStorage) DeleteKey(bucket string, key string) error {

	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		return err
	}

	// if the bucket doesn't exist, return an error
	if b == "" {
		return fmt.Errorf("bucket does not exist")
	}

	// unmashal the bucket into a struct
	bucketStruct := make(map[string]string)
	err = json.Unmarshal([]byte(b), &bucketStruct)
	if err != nil {
		return err
	}

	// try to find the key in the bucket
	for k := range bucketStruct {
		if k == key {
			delete(bucketStruct, k)
		}
	}

	// Marshal the bucket back to JSON
	bucketValueJSON, err := json.Marshal(bucketStruct)
	if err != nil {
		return err
	}

	// Set the bucket's value
	err = r.Db.Set(bucket, string(bucketValueJSON))
	if err != nil {
		return err
	}

	return nil
}

func (r RaftStorage) DeleteBucket(bucket string) error {

	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		return err
	}

	// if the bucket doesn't exist, return an error
	if b == "" {
		return fmt.Errorf("bucket does not exist")
	}

	// delete the bucket
	err = r.Db.Delete(bucket)
	if err != nil {
		return err
	}

	return nil
}

func (r RaftStorage) BucketExists(bucket string) bool {
	// get the bucket (aka key)
	b, err := r.Db.Get(bucket)
	if err != nil {
		return false
	}

	// if the bucket doesn't exist, return false
	if b == "" {
		return false
	}

	// if the bucket exists, return true
	return true
}
