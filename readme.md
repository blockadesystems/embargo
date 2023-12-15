# Embargo

## Description

The project is still in the early stages of development and is not ready for production use.

This is a simple secrets storage system. It is built using Golang. The data in Embargo is encrypted using AES-256-GCM encryption. The API is not compatible with any other system, though it is inspired by existing systems. The database layer is abstracted in such a way that other databases can be used in the future. Today Cassandra and in-memory databases are supported.  If in-memory is used, only one instance of the Embargo can be run. If Cassandra is used, multiple instances of the Embargo can be run.


## Usage

Embargo provides a simple REST API for storing and retrieving secrets. The API is documented below. In the future, the system may support GRPC as well.

When first started a call to /sys/init is needed to initialize the vault. This will generate a root key that is used to encrypt the vault. A set of shares are also generated using Shamir's Secret Sharing algorithm. The root key and shares are not stored anywhere. The shares will be provided in the response from /sys/init and should be stored securely.

Once the system is initialized, the vault will be sealed. This means that the vault is encrypted and cannot be accessed. To unseal the vault, a call to /sys/unseal is needed. This call will require a number of shares to be provided. The number of shares needed is determined by the number of shares generated during the init call. Once the vault is unsealed, it will remain unsealed until the system is restarted.

## Running

### Docker

The easiest way to run Embargo is using Docker. The following command will run Embargo using an in-memory database.

```bash
docker run -p 8080:8080 -e EMBARGO_AUTO_UNSEAL=true -e EMBARGO_AUTO_UNSEAL_KEYS=<share_1>,<share_2>,<share_3> embargo
```

The following command will run Embargo using Cassandra.

```bash
docker run -p 8080:8080 -e EMBARGO_STORAGE_TYPE=cassandra -e EMBARGO_CASSANDRA_HOSTS=<cassandra_host_1>,<cassandra_host_2> -e EMBARGO_CASSANDRA_USERNAME=<username> -e EMBARGO_CASSANDRA_PASSWORD=<password> embargo
```

### Binary

To run Embargo without Docker, download the latest release from the releases page. The following command will run Embargo using an in-memory database. The binary will be configured using environment variables.

```bash

```bash
./embargo server
```

## Configuration

Embargo can be configured using environment variables. The following variables are supported:

EMBARGO_ADDRESS - Address the Embargo server will listen on. If not set it defaults to 127.0.0.1

EMBARGO_PORT - The port the Embargo server will listen on. If not set it defaults to 8080.

EMBARGO_TLS_DISABLE - If set to true, TLS will be disabled. If not set, TLS will be enabled. If TLS is enabled, EMBARGO_TLS_CERT_FILE and EMBARGO_TLS_KEY_FILE must be set. If EMBARGO_TLS_DISABLE is not set, it is defaulted to false.

EMBARGO_TLS_CERT_FILE - The path to the TLS certificate file. This is only used if TLS is enabled.

EMBARGO_TLS_KEY_FILE - The path to the TLS key file. This is only used if TLS is enabled.

EMBARGO_AUTO_UNSEAL - If set to true, the vault will automatically unseal itself on startup. This is useful for testing. If not set, the vault will need to be unsealed manually.

EMBARGO_AUTO_UNSEAL_KEYS - A comma separated list of keys to use to unseal the vault. This is only used if VAULT_AUTO_UNSEAL is set to true.

EMBARGO_LOG_LEVEL - The log level to use. If not set it defaults to "info". Valid options are "debug", "info", "warn", "error", "fatal", and "panic".

EMBARGO_STORAGE_TYPE - The type of storage to use. Currently options are "memory" and "cassandra". If not set, "memory" will be used. If "memory" is used only one instance of the Embargo can be run. If "cassandra" is used, multiple instances of the Embargo can be run.

EMBARGO_FILE - Used only if `EMBARGO_STORAGE_TYPE` is set to `memory`. The file to use to store the data. If not set it defaults to `embargo.db`

EMBARGO_CASSANDRA_HOSTS - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Comma separated list of IP address for the Cassandra servers.

EMBARGO_CASSANDRA_USERNAME - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Username used to connect to Cassandra servers.

EMBARGO_CASSANDRA_PASSWORD - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Password used to connect to the Cassandra servers.

EMBARGO_CASSANDRA_KEYSPACE - Used only if `EMBARGO_STORAGE_TYPE` is set to `cassandra`. Keyspace to use in Cassandra. If not set it will default to `embargo`

### API
Path | Methods
---- | ----
**sys endpoints** |
[/sys/init](#post-sysinit) | `GET` `POST`
[/sys/seal-status](#get-sysseal-status) | `GET`
[/sys/unseal](#post-sysunseal) | `POST`
[/sys/mounts](#get-sysmounts) | `GET`
[/sys/mounts/:mount](#get-sysmountsmount) | `GET` `POST`
[/sys/mounts/:mount/tune](#post-sysmountsmounttune) | `GET` `POST`
[/sys/rekey/init](#get-sysrekeyinit) | `GET` `POST` `DELETE`
[/sys/rekey/update](#post-sysrekeyupdate) | `POST`
**kv endpoints** |
[/kv/:mount/data/:path](#get-kvmountdatapath) | `GET` `POST`
[/kv/:mount/delete/:path](#delete-kvmountdeletepath) | `DELETE` `POST`
[/kv/:mount/undelete/:path](#post-kvmountundeletepath) | `POST`
[/kv/:mount/destroy/:path](#post-kvmountdestroypath) | `POST`
[/kv/:mount/metadata/:path](#list-kvmountmetadatapath) | `LIST`
**auth endpoints** |
[/auth/token](#post-authtoken) | `POST`
[/auth/token/renew](#post-authtokenrenew) | `POST`
[/auth/policies](#get-authtokenpolicies) | `GET` `POST`
[/auth/policies/:policy](#get-authpoliciespolicy) | `GET` `DELETE`


#### POST /sys/init

Initializes the vault. This will generate a root key and a set of shares. The root key and shares are not stored anywhere. The shares will be provided in the response from /sys/init and should be stored securely.

##### Parameters
- `shares` `int <required>` - The number of shares to generate. This should be greater than 1.
- `threshold` `int <required>` - The number of shares needed to unseal the vault. This should be less than or equal to the number of shares.
##### Request
```bash
curl  --header  "Content-Type:application/json" -X  POST \
--data  '{"shares": 5, "threshold": 2}'  http://127.0.0.1:8080/sys/init
```

##### Response
```JSON
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
##### Request
```bash
curl  --header  "Content-Type:application/json" -X  GET \
http://127.0.0.1:8080/sys/init
```

##### Response
```JSON
{"initialized":true}
```

#### GET /sys/seal-status

Returns the status of the vault.
##### Request
```bash
curl  --header  "Content-Type:application/json" -X  GET \
http://127.0.0.1:8080/sys/seal-status
```

##### Response  
```JSON
{"sealed":false}
```

#### POST /sys/unseal

Unseals the vault. This will need to be called with a unique share repeatedly until the threshold is met. The number of shares needed is determined by the number of shares generated during the init call. Once the vault is unsealed, it will remain unsealed until the system is restarted.

If the vault is already unsealed, this call will return an error.

If an invalid share is provided, the process will reset and the share will need to be provided again.

##### Parameters
- `key` `string <required>` - A share generated during the init process.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"key": "<share>"}'  http://127.0.0.1:8080/sys/unseal
```

##### Response
```JSON
{
    "number": 1,
    "progress": "1/2",
    "sealed": true,
    "threshold": 2
}
```

#### GET /sys/mounts

Returns a list of mount points.
##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  GET  http://127.0.0.1:8080/sys/mounts
```

##### Response
```JSON
{
    "data": {
        "policies/": {
            "config": {
                "ttl": "",
                "max_versions": 0
            },
            "created_at": "2023-11-28T23:05:08Z",
            "description": "Policies mount",
            "type": "policies",
            "updated_at": "2023-11-28T23:05:08Z"
        },
        "sys/": {
            "config": {
                "ttl": "",
                "max_versions": 0
            },
            "created_at": "2023-11-28T23:05:08Z",
            "description": "System mount",
            "type": "sys",
            "updated_at": "2023-11-28T23:05:08Z"
        },
        "teststore/": {
            "config": {
                "ttl": "0s",
                "max_versions": 0
            },
            "created_at": "2023-11-22T13:15:54Z",
            "description": "",
            "type": "kv",
            "updated_at": "2023-11-22T13:15:54Z"
        },
        "tokens/": {
            "config": {
                "ttl": "",
                "max_versions": 0
            },
            "created_at": "2023-11-28T23:05:08Z",
            "description": "Tokens mount",
            "type": "tokens",
            "updated_at": "2023-11-28T23:05:08Z"
        }
    },
    "total": 4
}
```

#### GET /sys/mounts/:mount

Returns information about a mount point.
##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  GET  http://127.0.0.1:8080/sys/mounts/<mount>
```

##### Response
```JSON
{
    "config": {
        "ttl": "0s",
        "max_versions": 0
    },
    "created_at": "2023-11-29T14:15:40Z",
    "description": "",
    "path": "<mount>",
    "type": "kv",
    "updated_at": "2023-11-29T14:15:40Z"
}
```

#### POST /sys/mounts/:mount

Creates a new mount point. Mount points are used to logically separate secrets. For example, you may want to store secrets for different environments in different mount points.

##### Parameters
- `mount` `string <required>` - The path to mount the secret at. This should be unique.
- `type` `string <required>` - The type of mount. Currently only "kv" is supported.
- `description` `string` - A description of the mount point.
- `config` `object` - Configuration for the mount point. Currently only "ttl" and "max_versions" are supported.
- `config.ttl` `string` - The time to live for secrets in the mount point. If not set, secrets will not expire.
- `config.max_versions` `int` - The maximum number of versions to keep for each secret. If not set, all versions will be kept.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"mount": "<mount>", "type": "kv", "description": "<description>", \
"config": {"ttl": "<ttl>", "max_versions": <max_versions>}}' \
http://127.0.0.1:8080/sys/mounts/<mount>
```

##### Response
```JSON
{
    "message": "Mount created",
    "mount": {
        "config": {
            "ttl": "0s",
            "max_versions": 0
        },
        "created_at": "2023-11-29T14:15:40Z",
        "description": "",
        "path": "<mount>",
        "type": "kv",
        "updated_at": "2023-11-29T14:15:40Z"
    }
}
```

#### GET /sys/mounts/:mount/tune

Returns information about a mount point.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  GET  http://127.0.0.1:8080/sys/mounts/<mount>/tune
```

##### Response
```JSON
{
    "ttl": "0s",
    "max_versions": 0
}
```

#### POST /sys/mounts/:mount/tune

Updates the configuration for a mount point.

##### Parameters
- `mount` `string <required>` - The path to mount the secret at. This should be unique.
- `ttl` `string` - The time to live for secrets in the mount point. If not set, secrets will not expire.
- `max_versions` `int` - The maximum number of versions to keep for each secret. If not set, all versions will be kept.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"ttl": "<ttl>", "max_versions": <max_versions>}' \
http://127.0.0.1:8080/sys/mounts/<mount>/tune
```

##### Response
Blank response with a 204 status code.

#### GET /sys/rekey/init

Get the status of the rekey process.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' -X  GET  http://127.0.0.1:8080/sys/rekey/init
```

##### Response
```JSON
{
    "nonce": "fc2dbf91-4e8c-4565-963b-1482235d8529",
    "progress": 0,
    "required": 2,
    "shares": 5,
    "started": true,
    "threshold": 2
}
```

#### POST /sys/rekey/init

Starts the rekey process. The rekey process will generate a new root key and a new set of shares. The system will be rekeyed once the threshold number of shares have been provided to the /sys/rekey/update endpoint.

##### Parameters
- `shares` `int <required>` - The number of shares to generate. This should be greater than 1.
- `threshold` `int <required>` - The number of shares needed to unseal the vault. This should be less than or equal to the number of shares.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' -X  POST --data  '{"shares": 5, "threshold": 2}'  http://127.0.0.1:8080/sys/rekey/init
```

##### Response
```JSON
{
    "nonce": "fc2dbf91-4e8c-4565-963b-1482235d8529",
    "progress": 0,
    "required": 2,
    "shares": 5,
    "started": true,
    "threshold": 2
}
```

#### DELETE /sys/rekey/init

Cancels the rekey process.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' -X  DELETE  http://127.0.0.1:8080/sys/rekey/init
```

##### Response
```JSON
{"message":"rekey canceled"}
```

#### POST /sys/rekey/update

Updates the rekey process. This should be called with a unique share repeatedly until the threshold is met. The number of shares needed is determined by the number of shares generated during the init call. Once the threshold is met, the system will be rekeyed.

##### Parameters
- `key` `string <required>` - A share generated during the init process.
- `nonce` `string <required>` - The nonce returned from the /sys/rekey/init endpoint.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' -X  POST --data  '{"key": "<share>", "nonce": "<nonce>"}'  http://127.0.0.1:8080/sys/rekey/update
```

##### Response
```JSON
{
    "progress": 1,
    "required": 2,
    "shares": 5,
    "started": true,
    "threshold": 2
}
```

#### GET /kv/:mount/data/:path

Returns the value of a secret.

##### Parameters
- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.
- `version` `int` - URL parameter to specify the version of the secret to retrieve. If not set, the latest version will be returned.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  GET  http://127.0.0.1:8080/kv/<mount>/data/<path>?version=<version>
```

##### Response
```JSON
{
    "data": {
        "data": {
            "foo": "bar"
        },
        "metadata": {
            "created_time": "2023-11-28T00:05:12Z",
            "custom_metadata": {},
            "deletion_time": "",
            "destroyed": false,
            "version": 2
        }
    }
}
```

#### POST /kv/:mount/data/:path

Creates a new secret or updates an existing secret.

##### Parameters
- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.
- `data` `object <required>` - The data to store in the secret.
- `metadata` `object` - Additional metadata to store with the secret.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"data": {"foo": "bar"}, "metadata": {"custom_metadata": {}}}' \
http://127.0.0.1:8080/kv/<mount>/data/<path>
```

##### Response
```JSON
{
    "data": {
        "data": {
            "foo": "bar"
        },
        "metadata": {
            "created_time": "2023-11-28T00:05:12Z",
            "custom_metadata": {},
            "deletion_time": "",
            "destroyed": false,
            "version": 2
        }
    }
}
```

#### DELETE /kv/:mount/delete/:path

Marks a secret as deleted. The secret will not be removed from the database, but it will not be returned in future requests. If the deleted version is specified in a request, it will be returned with a deletion_time set and the data will be blank.

##### Parameters
- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  DELETE  http://127.0.0.1:8080/kv/<mount>/delete/<path>
```

##### Response
Blank response with a 204 status code.

#### POST /kv/:mount/delete/:path

Marks a secret as deleted. The secret will not be removed from the database, but it will not be returned in future requests. If the deleted version is specified in a request, it will be returned with a deletion_time set and the data will be blank.

##### Parameters
- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.
- `versions` `array <required>` - An array of versions to delete.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"versions": [1, 2]}' \
http://127.0.0.1:8080/kv/<mount>/delete/<path>
```

##### Response
Blank response with a 204 status code.

#### POST /kv/:mount/undelete/:path

Undeletes a secret. The secret will be returned in future requests.

##### Parameters
- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.
- `versions` `array <required>` - An array of versions to undelete.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"versions": [1, 2]}' \
http://127.0.0.1:8080/kv/<mount>/undelete/<path>
```

##### Response
Blank response with a 204 status code.

#### POST /kv/:mount/destroy/:path

Destroys a secret. The version(s) of the secret will be removed from the database.

##### Parameters

- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.
- `versions` `array <required>` - An array of versions to destroy.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X  POST --data  '{"versions": [1, 2]}' \
http://127.0.0.1:8080/kv/<mount>/destroy/<path>
```

##### Response
Blank response with a 204 status code.

#### LIST /kv/:mount/metadata/:path

Returns a list of versions for a secret and their metadata.

##### Parameters
- `mount` `string <required>` - The mount point the secret is stored in.
- `path` `string <required>` - The path to the secret.

##### Request
```bash
curl  --header  "Content-Type:application/json" --header  'X-Embargo-Token:<token>' \
-X LIST  http://127.0.0.1:8080/kv/<mount>/metadata/<path>
```

##### Response
```JSON
{
    "data": {
        "created_at": "2023-11-29T20:07:01Z",
        "current_version": 1,
        "delete_version_after": 0,
        "max_versions": 3,
        "oldest_version": 1,
        "custom_metadata": {},
        "versions": {
            "1": {
                "created_time": "2023-11-29T20:07:01Z",
                "deleted_time": "",
                "destroyed": false
            }
        }
    }
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
```JSON
{
    "token": "<token>",
    "display_name": "token1",
    "created_at": "2023-11-29T19:16:29.230328-05:00",
    "updated_at": "2023-11-29T19:16:29.230328-05:00",
    "ttl": 0,
    "renewable": false,
    "root": false,
    "orphan": false,
    "parent": "<parent_id>",
    "policies": [
        "<policy_id>"
    ],
    "metadata": null
}
```

#### POST /auth/token/renew

Renew a token.

##### Parameters
- `increment` `int` - Minutes to extend the token's TTL.  Set to `0` to use the token's original TTL.

##### Request
```bash
curl  --header  "Content-Type:application/json"  --header 'X-Embargo-Token:<token>' \
-X  POST --data  '{"increment": 0}' \
 http://127.0.0.1:8080/auth/token/renew
```

##### Response
```JSON
{"message":"token renewed"}
```

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

#### GET /auth/policies/:policy

Get a policy by ID.
##### Request
```bash
curl  --header  "Content-Type:application/json"  --header  'X-Embargo-Token:<token>' -X  GET  http://127.0.0.1:8080/auth/policies/<policy_id>
```

##### Response
```bash
{
    "policy_id": "e0ebdfad-2994-4ead-ad6e-aaa67d89c048",
    "policy_name": "get/post /kv/teststore/",
    "created_at": "2023-11-30T08:32:33.404649-05:00",
    "updated_at": "2023-11-30T08:32:33.404649-05:00",
    "paths": [
        {
            "path": "/kv/teststore/",
            "method": "GET"
        },
        {
            "path": "/kv/teststore/",
            "method": "POST"
        }
    ]
}
```

#### DELETE /auth/policies/:policy

Delete a policy by ID.

##### Request
```bash
curl  --header  "Content-Type:application/json"  --header  'X-Embargo-Token:<token>' -X  DELETE  http://127.0.0.1:8080/auth/policies/<policy_id>
```

##### Response
```bash
{"message":"policy deleted"}
```