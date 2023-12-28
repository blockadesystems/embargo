package raft

import (
	// "net/http"
	// "strconv"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"

	// "go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/raft/v3"
	"go.etcd.io/etcd/server/v3/etcdserver/api/rafthttp"
	// stats "go.etcd.io/etcd/server/v3/etcdserver/api/v2stats"
)

// type BoltDB struct {
// 	*bolt.DB
// 	node    raft.Node
// 	storage *raft.MemoryStorage
// }

// func NewBoltDB(path string, id uint64, peers []raft.Peer) (*BoltDB, error) {
// 	println("raft server starting")
// 	db, err := bolt.Open(path, 0600, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	storage := raft.NewMemoryStorage()
// 	uid := uuid.New()
// 	// convet uid to uint64
// 	newId := uint64(uid.ID())
// 	c := &raft.Config{
// 		ID:              newId,
// 		ElectionTick:    10,
// 		HeartbeatTick:   1,
// 		Storage:         storage,
// 		MaxSizePerMsg:   4096,
// 		MaxInflightMsgs: 256,
// 	}

// 	node := raft.StartNode(c, peers)
// 	println("raft server started")
// 	println(node)
// 	println("Node status: ", node.Status().String())

// 	return &BoltDB{
// 		DB:      db,
// 		node:    node,
// 		storage: storage,
// 	}, nil
// }

// Implement methods to interact with the database and the raft node...

type BoltDB struct {
	*bolt.DB
	node      raft.Node
	storage   *raft.MemoryStorage
	transport *rafthttp.Transport
}

func NewBoltDB(path string, id uint64, peers []raft.Peer, cluster string) (*BoltDB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	storage := raft.NewMemoryStorage()
	uid := uuid.New()
	// convet uid to uint64
	id = uint64(uid.ID())
	c := &raft.Config{
		ID:              id,
		ElectionTick:    10,
		HeartbeatTick:   1,
		Storage:         storage,
		MaxSizePerMsg:   4096,
		MaxInflightMsgs: 256,
	}

	node := raft.StartNode(c, peers)

	// Create a new HTTP transport
	// transport := &rafthttp.Transport{
	// 	ID:          types.ID(c.ID),
	// 	ClusterID:   types.ID(id),
	// 	Raft:        node,
	// 	ServerStats: stats.NewServerStats("", ""),
	// 	LeaderStats: stats.NewLeaderStats(strconv.Itoa(int(id))),
	// 	ErrorC:      make(chan error),
	// }
	var transport rafthttp.Transporter

	transport.Start()

	// Create a new HTTP server and add the Raft handler
	// srv := http.Server{
	// 	Handler: transport.Handler(),
	// }

	// go srv.Serve(listener)

	return &BoltDB{
		DB:      db,
		node:    node,
		storage: storage,
		// transport: transport,
	}, nil
}
