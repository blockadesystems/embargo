# Init the system
curl --header "Content-Type:application/json" --request POST --data '{"secret_shares":5, "secret_threshold":2}' http://127.0.0.1:8080/sys/init | jq --indent 4

# Unseal the system
curl --header "Content-Type:application/json" --request POST --data '{"key":"<key1>"}' http://127.0.0.1:8080/sys/unseal | jq --indent 4
curl --header "Content-Type:application/json" --request POST --data '{"key":"<key2>"}' http://127.0.0.1:8080/sys/unseal | jq --indent 4

# Create a policies
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<root_token>' --request POST --data '{"policy_name":"get/post /kv/teststore/", "paths":[{"path": "/kv/teststore/", "method": "get"},{"path": "/kv/teststore/", "method": "post"}]}' http://127.0.0.1:8080/auth/policies | jq --indent 4
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<root_token>' --request POST --data '{"policy_name":"get/post /kv/teststore2/", "paths":[{"path": "/kv/teststore2/", "method": "get"},{"path": "/kv/teststore2/", "method": "post"}]}' http://127.0.0.1:8080/auth/policies | jq --indent 4

# Create tokens
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<root_token>' --request POST --data '{"display_name":"token1", "ttl":0, "root":false, "orphen":false, "policies":["<policy1>"]}' http://127.0.0.1:8080/auth/token | jq --indent 4
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<root_token>' --request POST --data '{"display_name":"token2", "ttl":0, "root":false, "orphen":false, "policies":["<policy2>"]}' http://127.0.0.1:8080/auth/token | jq --indent 4

# Create a kv mount
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<root_token>' --request POST --data '{"type":"kv"}' http://127.0.0.1:8080/sys/mounts/teststore | jq --indent 4
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<root_token>' --request POST --data '{"type":"kv"}' http://127.0.0.1:8080/sys/mounts/teststore2 | jq --indent 4

# Write to kv
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token1>' --request POST --data '{"data":{"mykey": "teststore value"}}' http://127.0.0.1:8080/kv/teststore/data/item1 | jq --indent 4
# should fail
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token1>' --request POST --data '{"data":{"mykey": "teststore2 value"}}' http://127.0.0.1:8080/kv/teststore2/data/test1 | jq --indent 4
# Now with the correct token
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token2>' --request POST --data '{"data":{"mykey": "teststore2 value"}}' http://127.0.0.1:8080/kv/teststore2/data/test1 | jq --indent 4
# update the value
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token2>' --request POST --data '{"data":{"mykey": "teststore2 value update"}}' http://127.0.0.1:8080/kv/teststore2/data/test1 | jq --indent 4
# read the value
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token2>' --request GET http://127.0.0.1:8080/kv/teststore2/data/test1 | jq --indent 4
# read the value with the wrong token
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token1>' --request GET http://127.0.0.1:8080/kv/teststore2/data/test1 | jq --indent 4
# read version 1 of the value
curl --header "Content-Type:application/json" --header 'X-Embargo-Token:<token2>' --request GET 'http://127.0.0.1:8080/kv/teststore2/data/test1?version=1' | jq --indent 4

