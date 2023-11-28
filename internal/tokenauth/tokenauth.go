/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package tokenauth

import (
	"encoding/json"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"

	"github.com/blockadesystems/embargo/internal/storage"
)

// Embargo tokens are custom tokens that are used to authenticate
// Tokens presented to the end users will have the following format:
// embargo_toke_<token_id>_tokenhash

type EmbargoToken struct {
	TokenID     uuid.UUID
	TokenHash   string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Ttl         int
	Renewable   bool
	Root        bool
	Orphan      bool
	Parent      uuid.UUID
	Policies    []uuid.UUID
	Metadata    map[string]string
}

type PostedTokenRequest struct {
	DisplayName string            `json:"display_name"`
	Ttl         int               `json:"ttl"`
	Renewable   bool              `json:"renewable"`
	Root        bool              `json:"root"`
	Orphan      bool              `json:"orphan"`
	Policies    []uuid.UUID       `json:"policies"`
	Metadata    map[string]string `json:"metadata"`
}

type PostedTokenRenewRequest struct {
	Ttl int `json:"duration"`
}

type EmbargoTokenResponse struct {
	Token       string `json:"token"`
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Ttl         int
	Renewable   bool
	Root        bool
	Orphan      bool
	Parent      uuid.UUID
	Policies    []uuid.UUID
	Metadata    map[string]string
}

type EmbargoPolicy struct {
	PolicyID   uuid.UUID
	PolicyName string
	Created_at time.Time
	Updated_at time.Time
	Paths      []PolicyPath
}

type PolicyPath struct {
	Path   string
	Method string
}

type PostedPolicyRequest struct {
	PolicyName string       `json:"policy_name" validate:"required"`
	Paths      []PolicyPath `json:"paths" validate:"required"`
}

type GetPoliciesResponse struct {
	Data  []EmbargoPolicy `json:"data"`
	Total int             `json:"total"`
}

//
// UTILS
//

func randomString(n int) string {
	var seedRand = rand.New(rand.NewSource(time.Now().UnixNano()))

	var letters []rune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*?><=")
	alphabetSize := len(letters)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		// ch := letters[rand.Intn(alphabetSize)]
		ch := letters[seedRand.Intn(alphabetSize)]
		sb.WriteRune(ch)
	}
	s := sb.String()
	return s
}

//
// TOKENS
//

func checkTokenAccessToPolicy(tokenID string, policyID string) bool {
	db := storage.GetStore()
	tokenJSON, err := db.ReadKey("embargo_tokens", tokenID, false)
	if err != nil {
		println("Error reading token")
		return false
	}
	var token EmbargoToken
	err = json.Unmarshal([]byte(tokenJSON), &token)
	if err != nil {
		println("Error unmarshalling token")
		return false
	}

	if token.Root {
		return true
	}

	for _, policy := range token.Policies {
		if policy.String() == policyID {
			return true
		}
	}

	return false
}

// Create a new Embaro token
func CreateEmbargoToken(name string, ttl int, renewable bool, root bool, orphen bool, parent uuid.UUID, policies []uuid.UUID, metadata map[string]string) (EmbargoToken, string) {
	db := storage.GetStore()

	key := randomString(32)
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		println("Error generating token hash")
		println(err)
	}

	token := EmbargoToken{
		TokenID:     uuid.New(),
		TokenHash:   string(hash),
		DisplayName: name,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Ttl:         ttl,
		Renewable:   renewable,
		Root:        root,
		Orphan:      orphen,
		Parent:      parent,
		Policies:    policies,
		Metadata:    metadata,
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		println("Error marshalling token")
		println(err)
	}

	err = db.CreateKey("embargo_tokens", token.TokenID.String(), string(tokenJSON), false)
	if err != nil {
		println("Error creating token")
		println(err)
	}

	embToken := "embargo_token_" + token.TokenID.String() + "_" + key

	return token, embToken
}

// Check if a token is valid
func ValidateToken(token string) (EmbargoToken, bool) {
	db := storage.GetStore()

	// check if token is valid format
	tokenSplit := strings.Split(token, "_")
	if len(tokenSplit) != 4 {
		// println("Invalid token format")
		return EmbargoToken{}, false
	}

	// check if token exists in database
	tokenID := strings.Split(token, "_")[2]
	tokenHash := strings.Split(token, "_")[3]
	tokenJSON, err := db.ReadKey("embargo_tokens", tokenID, false)
	if err != nil {
		return EmbargoToken{}, false
	}

	// unmarshal token
	var embargoToken EmbargoToken
	err = json.Unmarshal([]byte(tokenJSON), &embargoToken)
	if err != nil {
		return EmbargoToken{}, false
	}

	// check if token is valid
	err = bcrypt.CompareHashAndPassword([]byte(embargoToken.TokenHash), []byte(tokenHash))
	if err != nil {
		return EmbargoToken{}, false
	}

	// check if token is expired
	if embargoToken.Ttl != 0 {
		if embargoToken.CreatedAt.Add(time.Duration(embargoToken.Ttl) * time.Minute).Before(time.Now()) {
			return EmbargoToken{}, false
		}
	}

	return embargoToken, true
}

// Middleware function to validate Embargo token
func ValidateEmbargoToken(next echo.HandlerFunc) echo.HandlerFunc {
	db := storage.GetStore()

	return func(c echo.Context) error {
		// check if token exists in header
		tokenString := c.Request().Header.Get("X-Embargo-Token")
		if tokenString == "" {
			return c.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		token, validToken := ValidateToken(tokenString)
		if !validToken {
			return c.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		// check if token is root
		if token.Root {
			return next(c)
		}

		// check if token has a policy that matches the path and method
		for _, policy := range token.Policies {
			// skip this for select paths
			if c.Request().RequestURI == "/auth/token/renew" {
				return next(c)
			}

			policyJSON, err := db.ReadKey("embargo_policies", policy.String(), false)
			if err != nil {
				return c.JSON(401, map[string]string{"error": "Unauthorized"})
			}

			var policyObj EmbargoPolicy
			err = json.Unmarshal([]byte(policyJSON), &policyObj)
			if err != nil {
				return c.JSON(401, map[string]string{"error": "Unauthorized"})
			}
			for _, path := range policyObj.Paths {
				var re = regexp.MustCompile("^" + path.Path + ".*")
				if re.MatchString(c.Request().RequestURI) {
					if path.Method == c.Request().Method {
						// println("Rock on")
						return next(c)
					}
				}
			}
		}

		// println("No matching policy")
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

}

func RenewToken(c echo.Context) error {
	db := storage.GetStore()
	inbound := new(PostedTokenRenewRequest)
	if err := c.Bind(inbound); err != nil {
		return err
	}

	// check if token exists in header
	tokenString := c.Request().Header.Get("X-Embargo-Token")
	if tokenString == "" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	token, validToken := ValidateToken(tokenString)
	if !validToken {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	// check if token is renewable
	if !token.Renewable {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	// update token
	token.Ttl = inbound.Ttl
	token.UpdatedAt = time.Now()

	updatedTokenJSON, err := json.Marshal(token)
	if err != nil {
		println("Error marshalling token")
		println(err)
	}

	err = db.UpdateKey("embargo_tokens", token.TokenID.String(), string(updatedTokenJSON))
	if err != nil {
		println("Error updating token")
		println(err)
	}

	return c.JSON(200, map[string]string{"message": "token renewed"})
}

func CreateToken(c echo.Context) error {
	db := storage.GetStore()
	inbound := new(PostedTokenRequest)
	if err := c.Bind(inbound); err != nil {
		return err
	}

	// Get requestor id and set it as the parent
	tokenString := c.Request().Header.Get("X-Embargo-Token")
	tokenID := strings.Split(tokenString, "_")[2]
	parent := uuid.Nil
	err := error(nil)

	// if not orphan, set parent to requestor
	if !inbound.Orphan {
		parent, err = uuid.Parse(tokenID)
		if err != nil {
			println("Error parsing token id")
			println(err)
		}
	}

	// if inbound.Root is true, check if requestor is root
	if inbound.Root {
		requestorTokenJSON, err := db.ReadKey("embargo_tokens", tokenID, false)
		if err != nil {
			println("Error reading token")
			return c.JSON(401, map[string]string{"error": "Unauthorized"})
		}
		var requestorToken EmbargoToken
		err = json.Unmarshal([]byte(requestorTokenJSON), &requestorToken)
		if err != nil {
			println("Error unmarshalling token")
			return c.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		if !requestorToken.Root {
			return c.JSON(401, map[string]string{"error": "Unauthorized"})
		}
	}

	// check if policies exist and requestor has access
	for _, policy := range inbound.Policies {
		_, err := db.ReadKey("embargo_policies", policy.String(), false)
		if err != nil {
			return c.JSON(400, map[string]string{"error": "policy does not exist"})
		}

		// check if requestor has access to policy
		tokenString := c.Request().Header.Get("X-Embargo-Token")
		tokenID := strings.Split(tokenString, "_")[2]
		if !checkTokenAccessToPolicy(tokenID, policy.String()) {
			return c.JSON(401, map[string]string{"error": "Unauthorized"})
		}
	}

	token, embToken := CreateEmbargoToken(inbound.DisplayName, inbound.Ttl, inbound.Renewable, inbound.Root, inbound.Orphan, parent, inbound.Policies, inbound.Metadata)

	// create response
	response := EmbargoTokenResponse{
		Token:       embToken,
		DisplayName: token.DisplayName,
		CreatedAt:   token.CreatedAt,
		UpdatedAt:   token.UpdatedAt,
		Ttl:         token.Ttl,
		Renewable:   token.Renewable,
		Root:        token.Root,
		Orphan:      token.Orphan,
		Parent:      token.Parent,
		Policies:    token.Policies,
		Metadata:    token.Metadata,
	}

	return c.JSON(200, response)
}

//
// POLICIES
//

func GetPolicies(c echo.Context) error {
	db := storage.GetStore()
	policies, err := db.ReadAllKeys("embargo_policies")
	if err != nil {
		println("Error reading policies")
		println(err)
	}

	var policyList []EmbargoPolicy
	for _, policy := range policies {
		var policyObj EmbargoPolicy
		err = json.Unmarshal([]byte(policy), &policyObj)
		if err != nil {
			println("Error unmarshalling policy")
			println(err)
		}
		policyList = append(policyList, policyObj)
	}

	policiesResponse := GetPoliciesResponse{
		Data:  policyList,
		Total: len(policyList),
	}

	return c.JSON(200, policiesResponse)
}

func CreatePolicy(c echo.Context) error {
	db := storage.GetStore()
	inbound := new(PostedPolicyRequest)
	if err := c.Bind(inbound); err != nil {
		return err
	}

	newPolicy := EmbargoPolicy{
		PolicyID:   uuid.New(),
		PolicyName: inbound.PolicyName,
		Created_at: time.Now(),
		Updated_at: time.Now(),
		Paths:      inbound.Paths,
	}

	// make sure methods are uppercase
	for i, path := range newPolicy.Paths {
		newPolicy.Paths[i].Method = strings.ToUpper(path.Method)
	}

	// get requestor token
	tokenString := c.Request().Header.Get("X-Embargo-Token")
	tokenID := strings.Split(tokenString, "_")[2]
	tokenJSON, err := db.ReadKey("embargo_tokens", tokenID, false)
	if err != nil {
		println("Error reading token")
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}
	var requestorToken EmbargoToken
	err = json.Unmarshal([]byte(tokenJSON), &requestorToken)
	if err != nil {
		println("Error unmarshalling token")
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	// check that requestor has access to inbound paths
	hasAccess := false
	for _, path := range newPolicy.Paths {
		for _, policy := range requestorToken.Policies {
			policyJSON, err := db.ReadKey("embargo_policies", policy.String(), false)
			if err != nil {
				println("Error reading policy")
			}
			var policyObj EmbargoPolicy
			err = json.Unmarshal([]byte(policyJSON), &policyObj)
			if err != nil {
				println("Error unmarshalling policy")
			}
			for _, policyPath := range policyObj.Paths {
				// check if requestor has access to base path
				println(policyPath.Path)
				println(path.Path)
				var re = regexp.MustCompile("^" + policyPath.Path + ".*")
				if re.MatchString(path.Path) {
					// if policyPath == path {
					// requestor has access, let them create the policy
					hasAccess = true
					break
				}
			}
		}
		// requestor does not have access, return unauthorized
		if requestorToken.Root {
			hasAccess = true
			break
		}
		// } else {
		// return c.JSON(401, map[string]string{"error": "Unauthorized"})
		// }
	}
	if !hasAccess {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	// create policy
	policyJSON, err := json.Marshal(newPolicy)
	if err != nil {
		println("Error marshalling policy")
		println(err)
	}
	err = db.CreateKey("embargo_policies", newPolicy.PolicyID.String(), string(policyJSON), false)
	if err != nil {
		println("Error creating policy")
		println(err)
	}

	return c.JSON(200, newPolicy)
}

func GetPolicy(c echo.Context) error {
	db := storage.GetStore()
	policyID := c.Param("policy")

	policyJSON, err := db.ReadKey("embargo_policies", policyID, false)
	if err != nil {
		println("Error reading policy")
		println(err)
	}

	var policy EmbargoPolicy
	err = json.Unmarshal([]byte(policyJSON), &policy)
	if err != nil {
		println("Error unmarshalling policy")
		println(err)
	}

	return c.JSON(200, policy)
}

func DeletePolicy(c echo.Context) error {
	db := storage.GetStore()
	policyID := c.Param("policy")

	// delete policy
	err := db.DeleteKey("embargo_policies", policyID)
	if err != nil {
		println("Error deleting policy")
		println(err)
	}

	return c.JSON(200, map[string]string{"message": "policy deleted"})
}
