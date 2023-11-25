# Embargo

## Description

The project is still in the early stages of development and is not ready for production use.

This is a simple secrets storage system. It is built using Golang. The data in Embargo is encrypted using AES-256-GCM encryption. The API is not compatible with any other system, though it is inspired by existing systems. The database layer is abstracted in such a way that other databases can be used in the future. Today Cassandra and in-memory databases are supported.  If in-memory is used, only one instance of the Embargo can be run. If Cassandra is used, multiple instances of the Embargo can be run.


## Usage

Embargo provides a simple REST API for storing and retrieving secrets. The API is documented below. In the future, the system may support GRPC as well.

When first started a call to /sys/init is needed to initialize the vault. This will generate a root key that is used to encrypt the vault. A set of shares are also generated using Shamir's Secret Sharing algorithm. The root key and shares are not stored anywhere. The shares will be provided in the response from /sys/init and should be stored securely.

Once the system is initialized, the vault will be sealed. This means that the vault is encrypted and cannot be accessed. To unseal the vault, a call to /sys/unseal is needed. This call will require a number of shares to be provided. The number of shares needed is determined by the number of shares generated during the init call. Once the vault is unsealed, it will remain unsealed until the system is restarted.

## Configuration

Embargo can be configured using environment variables. The following variables are supported:

EMBARGO_ADDRESS - Address the Embargo server will listen on. If not set it defaults to 127.0.0.1

EMBARGO_PORT - The port the Embargo server will listen on. If not set it defaults to 8080.

EMBARGO_AUTO_UNSEAL - If set to true, the vault will automatically unseal itself on startup. This is useful for testing. If not set, the vault will need to be unsealed manually.

EMBARGO_AUTO_UNSEAL_KEYS - A comma separated list of keys to use to unseal the vault. This is only used if VAULT_AUTO_UNSEAL is set to true.

EMBARGO_LOG_LEVEL - The log level to use. If not set it defaults to "info". Valid options are "debug", "info", "warn", "error", "fatal", and "panic".

EMBARGO_STORAGE_TYPE - The type of storage to use. Currently options are "memory" and "cassandra". If not set, "memory" will be used. If "memory" is used only one instance of the Embargo can be run. If "cassandra" is used, multiple instances of the Embargo can be run.

EMBARGO_CASSANDRA_HOSTS - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Comma separated list of IP address for the Cassandra servers.

EMBARGO_CASSANDRA_USERNAME - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Username used to connect to Cassandra servers.

EMBARGO_CASSANDRA_PASSWORD - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Password used to connect to the Cassandra servers.

EMBARGO_CASSANDRA_KEYSPACE - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Keyspace to use in Cassandra. If not set it will default to `embargo`

### API
Path | Methods
---- | ----
**sys endpoints** |
/sys/init | `GET` `POST`
/sys/seal-status | `GET`
/sys/unseal | `POST`
/sys/mounts | `GET`
/sys/mounts/:mount | `POST`
/sys/mounts/:mount/tune | `GET`
**kv endpoints** |
/kv/:mount/data/:path | `GET` `POST`
/kv/:mount/delete/:path | `DELETE` `POST`
/kv/:mount/undelete/:path | `POST`
/kv/:mount/destroy/:path | `POST`
/kv/:mount/metadata | `LIST`
/kv/:mount/metadata/:path | `LIST`
**auth endpoints** |
/auth/token | `POST`
/auth/token/renew | `POST`
/auth/token/policies | `GET` `POST`
/auth/token/policies/:policy | `GET` `DELETE`







#### GET /auth/policies
Get a list of policies.
##### Request
```bash
curl  --header  "Content-Type:application/json"  --header  'X-Embargo-Token:<token>' -X  GET  http://127.0.0.1:8080/auth/policies
```
##### Response
```bash
{
    "data": [
        {
            "PolicyID": "2a69459e-d8af-4115-a03b-86aca9f43da4",
            "PolicyName": "GET/POST bobstore",
            "Created_at": "2023-11-05T08:31:58.557386751-05:00",
            "Updated_at": "2023-11-05T08:31:58.557386824-05:00",
            "Paths": [
                {
                    "Path": "/kv/teststore/",
                    "Method": "GET"
                },
                {
                    "Path": "/kv/teststore/",
                    "Method": "POST"
                }
            ]
        }
    ],
    "total": 1
}
```
#### POST /auth/policies
Create a new policy.
##### Parameters  
- `policy_name` `string` - A display name for the policy
- `paths` `array: [{"path": string, "method": string}]` - Array of path, method objects. The path string has an implied wildcard at the end.  For example.  With the provided path `/kv/teststore` it will match `/kv/teststore/data/mykey` and `/kv/teststore2/data/otherkey`. While if there were a slash added like `/kv/teststore/` it would not. 

##### Request
```bash
curl  --header  "Content-Type:application/json"  --header  'X-Embargo-Token:<token>' -X  POST --data  '{"policy_name":"<name>", "paths":[{"path": "<path>", "method": "<method>"}]}'  http://127.0.0.1:8080/auth/policies
```
##### Response
```
{  
    "PolicyID": "f4316c5d-74d1-4ee3-b213-2a47535f0f4a",  
    "PolicyName": "get/post /kv/teststore/",  
    "Created_at": "2023-11-08T14:47:47.927282686-05:00",  
    "Updated_at": "2023-11-08T14:47:47.92728274-05:00",  
    "Paths": [  
        {  
            "Path": "/kv/teststore/",  
            "Method": "GET"  
        },
    ]  
}
```
#### POST /auth/token
Create a new token.
##### Parameters 
- `display_name` `string` - Display name for token.
- `ttl` `int` - Minutes until the token expires.  Set to `0` for a non-expiring token.
- `renewable` `bool` - If the token can be renewed
- `root` `bool` - If the token is a root token.  Can you be set to true if the requestor is also a root token.
- `orphan` `bool` - If set to true the token will not have a parent.
- `policies` `array [string]` - List of policy IDs.
- `metadata` `object` - Additional data.
##### Request
```bash
curl  --header  "Content-Type:application/json"  --header 'X-Embargo-Token:<token>' \
-X  POST --data  '{"display_name":"<name>", "ttl": 0, "renewable": false, \
"root": false, "orphan": false, "policies": ["<policy_id>"], "metadata": {"foo": "bar"}}' \
 http://127.0.0.1:8080/auth/token
```
##### Response
```

```

#### POST /kv/mount/:path

Create a new mount point. Mount points are used to logically separate secrets. For example, you may want to store secrets for different environments in different mount points.

##### Parameters 
- `path` `string <required>` - Provided in the URI of the request. The path to mount the secret at. This should be unique.
##### Request
```bash
curl  --header  "Content-Type:application/json"  --header  'X-Embargo-Token:<token>' \
-X  POST  http://127.0.0.1:8080/kv/mount/<path>
```


#### GET /kv/mounts/

Returns a list of mount points.


  

#### POST /kv/:mount/:path

Create a new secret.



  

#### GET /kv/:mount/:path?version=1

Retrieve a secret. If no version is provided, the latest version will be returned.


#### POST /sys/init

Initializes the vault. This will generate a root key and a set of shares. The root key and shares are not stored anywhere. The shares will be provided in the response from /sys/init and should be stored securely.

##### Parameters
- `secret_shares` `int <required>` - The number of shares to generate. This should be greater than 1.
- `secret_threshold` `int <required>` - The number of shares needed to unseal the vault. This should be less than or equal to the number of shares.
##### Request
```bash
curl  --header  "Content-Type:application/json" -X  POST \
--data  '{"shares": 5, "threshold": 2}'  http://127.0.0.1:8080/sys/init
```

##### Response
```
{
  "message": "The system has been initialized with 5 shares and a threshold of 2. The shares are listed below. Please store them in a safe place. When the system starts, you will need to unseal it with 2 of the 5 shares. The system does not store the shares or the generated root key. Without at least 2 shares, the system cannot be unsealed.",
  "rootToken": "<root_token>",
  "shares": [
    "<share_1>",
    "<share_2>",
    "<share_3>",
    "<share_4>",
    "<share_5>"
  ],
  "threshold": 2
}
```

#### GET /sys/init

Returns the status of the vault..



#### GET /sys/seal-status

Returns the status of the vault.
  

#### POST /sys/unseal

Unseals the vault. This will need to be called with a unique share repeatedly until the threshold is met. The number of shares needed is determined by the number of shares generated during the init call. Once the vault is unsealed, it will remain unsealed until the system is restarted.

If the vault is already unsealed, this call will return an error.

If an invalid share is provided, the process will reset and the share will need to be provided again.

##### Parameters
- `share` `string <required>` - A share generated during the init process.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"share": "<share>"}'  http://127.0.0.1:8080/sys/unseal
```
  



