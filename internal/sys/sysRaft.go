package sys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/blockadesystems/embargo/internal/encryption"
	"github.com/blockadesystems/embargo/internal/shared"
	"github.com/blockadesystems/embargo/internal/storage"
	"github.com/labstack/echo/v4"
)

// To join a raft cluster
// There must be a leader node running
// The joining node should be unsealed

type joinRaft struct {
	LeaderApiAddr string `json:"leader_api_addr"`
	Threshold     int    `json:"threshold"`
	SkipTlsVerify bool   `json:"skip_tls_verify"`
}

type joinRaftRequest struct {
	NodeId      string `json:"node_id"`
	ApiAddress  string `json:"api_address"`
	RaftAddress string `json:"raft_address"`
	NonVoter    bool   `json:"non_voter"`
	Key         string `json:"key"`
}

func encryptNodeKey(secret string) []byte {
	plaintext := []byte(secret)

	c, err := aes.NewCipher([]byte(encryption.RootKey))
	if err != nil {
		log.Println(err)
		return nil
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
		return nil
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		log.Println(err)
		return nil
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

func decryptNodeKey(ciphertext []byte, nodeId string) (string, bool) {

	key := []byte(encryption.RootKey)

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return "", false
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
		return "", false
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println(err)
		return "", false
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		return "", false
	}

	return string(plaintext), true
}

func RaftInit() {
	storage.RaftStoreInit()
	log.Println("Raft store started")
	time.Sleep(5 * time.Second)

	// loop until raft is ready
	// loopCounter := 0
	// for {
	// 	// Get the raft status
	// 	status := shared.RaftStore.Raft.Stats()
	// 	log.Println("raft status: ", status)

	// 	m2 := make(map[string]interface{}, len(status))
	// 	for k, v := range status {
	// 		m2[k] = v
	// 		log.Println(k, v)
	// 	}

	// 	numPeers, err := strconv.Atoi(m2["num_peers"].(string))
	// 	if err != nil {
	// 		numPeers = 0
	// 	}

	// 	if m2["state"] == "Leader" {
	// 		StartSys()
	// 		break
	// 	} else if m2["state"] == "Follower" && numPeers > 0 {
	// 		StartSys()
	// 		break
	// 	} else if loopCounter > 10 {
	// 		if m2["state"] == "Candidate" {
	// 			StartSys()
	// 			break
	// 		}
	// 		log.Println("Raft store not ready after 10 seconds")
	// 		break
	// 	} else {
	// 		log.Println("Raft store not ready, sleeping for 1 second")
	// 		time.Sleep(1 * time.Second)
	// 	}
	// 	loopCounter++
	// }
}

func BootstrapRaft(c echo.Context) error {
	log.Println("bootstrapping raft")
	returnData := make(map[string]interface{})
	if shared.StorageType != "raft" {
		// set return data as error. Init is not supported in raft mode
		returnData["message"] = "embargo is not running in raft mode. Bootstrap is only supported in raft mode"
		return c.JSON(http.StatusBadRequest, returnData)
	}

	db := storage.GetStore()

	// Check if the system has already been initialized. If so, return an error
	i, err := db.ReadKey("embargo_sys", "initialized", false)
	if err != nil {
		log.Println("Setting initialized var key to false")
		i = "false"
	}
	initialized, err := strconv.ParseBool(i)
	if err != nil {
		returnData["message"] = "Error reading initialized key"
		return c.JSON(http.StatusBadRequest, returnData)
	}
	if initialized {
		returnData["message"] = "system already initialized"
		return c.JSON(http.StatusBadRequest, returnData)
	}

	// Seed the storage
	log.Println("Creating buckets")
	storage.Store.CreateBucket("embargo_mounts")
	storage.Store.CreateBucket("embargo_sys")
	storage.Store.CreateBucket("embargo_tokens")
	storage.Store.CreateBucket("embargo_policies")

	// Set the initialized key to false
	err = db.UpdateKey("embargo_sys", "initialized", "false", false)
	if err != nil {
		log.Println("Error updating initialized key", err)
		panic(err)
	}

	// Start the system
	StartSys()
	// time.Sleep(5 * time.Second)

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

	returnData["message"] = "The system has been initialized with " + strconv.Itoa(r.Shares) + " shares and a threshold of " + strconv.Itoa(r.Threshold) + ". The shares are listed below. Please store them in a safe place. When the system starts, you will need to unseal it with " + strconv.Itoa(r.Threshold) + " of the " + strconv.Itoa(r.Shares) + " shares. The system does not store the shares or the generated root key. Without at least " + strconv.Itoa(r.Threshold) + " shares, the system cannot be unsealed."
	returnData["threshold"] = r.Threshold
	returnData["shares"] = res.Shares
	returnData["rootToken"] = res.RootToken

	return c.JSON(http.StatusOK, returnData)
}

func JoinRaftRequest(c echo.Context) error {
	r := new(joinRaftRequest)
	if err := c.Bind(r); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Check if the storage type is raft
	if shared.StorageType != "raft" {
		return c.JSON(http.StatusPreconditionFailed, "system not in raft mode")
	}

	// Check if this node is the leader
	if !shared.IsRaftLeader() {
		return c.JSON(http.StatusPreconditionFailed, "node is not the leader")
	}

	// Check if the node_id is set
	if r.NodeId == "" {
		return c.JSON(http.StatusBadRequest, "node_id required")
	}

	// Check if the api_address is set
	if r.ApiAddress == "" {
		return c.JSON(http.StatusBadRequest, "api_address required")
	}

	// Check if the raft_address is set
	if r.RaftAddress == "" {
		return c.JSON(http.StatusBadRequest, "raft_address required")
	}

	if r.Key != "" {
		// This is the key that was encrypted with the root key
		// The leader will decrypt it and add the node to the cluster

		// base64 decode the encrypted key
		encMessageText, err := base64.StdEncoding.DecodeString(r.Key)
		if err != nil {
			return c.JSON(http.StatusPreconditionFailed, "unable to decode key")
		}
		log.Println("encrypted key str: ", r.Key)
		log.Println("encrypted key: ", string(encMessageText))

		found := false
		for i, v := range shared.RaftClusterRequestData {
			if v.NodeId == r.NodeId {
				if v.NodeSecretString == string(encMessageText) {
					// Add the node to the cluster
					shared.RaftStore.Join(r.NodeId, v.RaftAddress)
					// Remove the shared.RaftClusterRequest from the shared.RaftClusterRequestData
					shared.RaftClusterRequestData = append(shared.RaftClusterRequestData[:i], shared.RaftClusterRequestData[i+1:]...)
					found = true
					break
				}
			}
		}

		if !found {
			return c.JSON(http.StatusPreconditionFailed, "node not found")
		}

		// Create a response
		resData := make(map[string]interface{})
		resData["message"] = "node added to the cluster"

		return c.JSON(http.StatusOK, resData)
	}

	// Create a random string and encrypt it with the root key
	// This will be the key to send to the new node
	// The new node will decrypt it with the root key
	// The new node will then send it back to the leader
	// The leader will then add the new node to the cluster
	// The new node will then be a non-voter
	// The new node will then be promoted to a voter
	// The new node will then be able to vote in the cluster
	nodeSecretStr := randomString(32)
	nodeSecretEnc := encryptNodeKey(nodeSecretStr)

	// base64 encode the encrypted key
	nodeSecretEncStr := base64.StdEncoding.EncodeToString(nodeSecretEnc)

	var recData = shared.RaftClusterRequest{
		NodeSecretString: nodeSecretStr,
		NodeId:           r.NodeId,
		RaftAddress:      r.RaftAddress,
	}

	// Append recData to the shared.RaftClusterRequestData
	shared.RaftClusterRequestData = append(shared.RaftClusterRequestData, recData)

	// Store the string and the node_id for future use

	// create response message
	log.Println("node secret str: ", nodeSecretStr)
	log.Println("encrypted key str: ", nodeSecretEncStr)
	log.Println("encrypted key: ", nodeSecretEnc)
	resData := make(map[string]interface{})
	resData["message"] = nodeSecretEncStr
	return c.JSON(http.StatusOK, resData)
}

func JoinRaft(c echo.Context) error {
	// JoinRaft tells a new node to join an existing raft cluster
	// The POST to this endpoint should contain the leader's API address and the threshold to unseal the system
	// After POSTing to this endpoint, the new node needs to be unsealed
	// The new node will then send a POST to the leader requesting to join the cluster
	// The leader will then send a POST to the new node with an encrypted key
	// The new node will decrypt the key using the root key and send it back to the leader

	// Get the request data
	r := new(joinRaft)
	if err := c.Bind(r); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Check if the storage type is raft
	if shared.StorageType != "raft" {
		return c.JSON(http.StatusPreconditionFailed, "system not in raft mode")
	}

	// Check if the leader address is set
	if r.LeaderApiAddr == "" {
		return c.JSON(http.StatusBadRequest, "leader_api_addr required")
	}

	// Check if the threshold is set
	if r.Threshold == 0 {
		return c.JSON(http.StatusBadRequest, "threshold required and must be greater than 0")
	}

	// Get the leader's raft status
	leaderStatus := shared.RaftStore.Raft.Stats()
	leader := leaderStatus["leader"]

	// Check if the leader is set
	if leader != "" {
		return c.JSON(http.StatusPreconditionFailed, "system already in raft cluster")
	}

	// Set the shared.Unseal
	unsealData := shared.UnsealData{
		Threshold: r.Threshold,
		Shares:    r.Threshold,
		Keys:      []string{},
	}
	shared.Unseal = unsealData

	// Set the shared.RaftJoinRequest
	shared.RaftJoinRequest.Address = r.LeaderApiAddr
	shared.RaftJoinRequest.SkipTlsVerify = r.SkipTlsVerify

	// Create a response
	resData := make(map[string]interface{})
	resData["message"] = "node is ready to join the cluster once unsealed"

	return c.JSON(http.StatusOK, resData)
}

func SendJoinRequest() {
	// SendJoinRequest sends a POST request to the leader to join the cluster
	// The leader will then send a POST to the new node with an encrypted key
	// The new node will decrypt the key using the root key and send it back to the leader
	time.Sleep(5 * time.Second)
	log.Println("sending join request to leader")

	// Build data to POST to leader
	ApiAddr := os.Getenv("EMBARGO_ADDRESS")
	ApiAddr += os.Getenv("EMBARGO_PORT")
	RaftAddr := os.Getenv("EMBARGO_RAFT_ADDRESS")
	data := map[string]interface{}{
		"node_id":      shared.RaftNodeId,
		"api_address":  ApiAddr,
		"raft_address": RaftAddr,
		"non_voter":    false,
	}

	// Send the POST request to the leader
	dataJs, err := json.Marshal(data)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	req, err := http.NewRequest("POST", "https://"+shared.RaftJoinRequest.Address+"/sys/raft/join-request", bytes.NewBuffer(dataJs))
	if err != nil {
		log.Println(err)
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: shared.RaftJoinRequest.SkipTlsVerify},
	}
	client := &http.Client{Transport: tr}

	// Send the join request to the leader
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	log.Println("response Status:", resp.Status)
	log.Println("response Headers:", resp.Header)
	log.Println("response Body:", string(body))

	// The response body should contain the encrypted key
	// convert the body to json
	var resData map[string]interface{}
	err = json.Unmarshal(body, &resData)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	// base64 decode the encrypted key
	// Decrypt the key using the root key
	// Send the decrypted key back to the leader
	// The leader will then add the new node to the cluster
	encMessageText, err := base64.StdEncoding.DecodeString(resData["message"].(string))
	if err != nil {
		log.Println(err)
		panic(err)
	}
	log.Println("encrypted key: ", encMessageText)
	log.Println("encrypted key str: ", resData["message"].(string))

	// Decrypt the key
	plaintext, decrypted := decryptNodeKey(encMessageText, shared.RaftNodeId)
	log.Println("decrypted key: ", plaintext)

	if !decrypted {
		log.Println("unable to decrypt key")
		return
	}

	// Send the decrypted key back to the leader
	// The leader will then add the new node to the cluster

	// base64 encode the decrypted key
	decryptedKeyStr := base64.StdEncoding.EncodeToString([]byte(plaintext))

	// Build data to POST to leader
	data = map[string]interface{}{
		"node_id":      shared.RaftNodeId,
		"api_address":  ApiAddr,
		"raft_address": RaftAddr,
		"non_voter":    false,
		"key":          decryptedKeyStr,
	}

	// Send the POST request to the leader
	dataJs, err = json.Marshal(data)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	req, err = http.NewRequest("POST", "https://"+shared.RaftJoinRequest.Address+"/sys/raft/join-request", bytes.NewBuffer(dataJs))
	if err != nil {
		log.Println(err)
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send the join request to the leader
	resp, err = client.Do(req)
	if err != nil {
		log.Println(err)
		panic(err)
	}
	defer resp.Body.Close()

	// Remove the shared.RaftJoinRequest
	shared.RaftJoinRequest.Address = ""
}

// raft
func GetLeader(c echo.Context) error {
	leader, leaderId := shared.RaftStore.Raft.LeaderWithID()
	// Create the response data
	resData := make(map[string]interface{})
	resData["leader"] = leader
	resData["leader_id"] = leaderId
	log.Println("leader: ", leader)

	return c.JSON(http.StatusOK, resData)
}

func GetRaftStatus(c echo.Context) error {
	// Get the raft status
	status := shared.RaftStore.Raft.Stats()

	// Create the response data
	resData := make(map[string]interface{})
	resData["status"] = status

	return c.JSON(http.StatusOK, resData)
}
