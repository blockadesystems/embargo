/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"

	"github.com/blockadesystems/embargo/internal/shared"
	"github.com/google/uuid"
)

// RootKey is the key used to encrypt and decrypt encryption keys
var RootKey string

// EncKeys is the list of encryption keys used to encrypt and decrypt secrets
var EncKeys shared.EncryptionKeyList

func DecryptSecret(ciphertext []byte, keyId uuid.UUID) (string, error) {
	var key []byte

	// get the key
	if EncKeys.ActiveKey.Id == keyId {
		key = []byte(EncKeys.ActiveKey.Key)
	} else {
		for _, k := range EncKeys.OldKeys {
			if k.Id == keyId {
				key = []byte(k.Key)
			}
		}
	}

	if key == nil {
		log.Println("key not found")
		return "", nil
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println(err)
		return "", err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return string(plaintext), nil
}

func EncryptSecret(secret string) ([]byte, error) {
	// key := []byte(RootKey)
	key := []byte(EncKeys.ActiveKey.Key)
	// make sure we have a key
	if key == nil {
		log.Println("key not found")
		return nil, nil
	}

	plaintext := []byte(secret)

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		log.Println(err)
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func DecryptKeys(ciphertext []byte) (string, error) {
	key := []byte(RootKey)

	if key == nil {
		log.Println("key not found")
		return "", nil
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println(err)
		return "", err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return string(plaintext), nil
}

func EncryptKeys(secret string) ([]byte, error) {
	key := []byte(RootKey)
	plaintext := []byte(secret)

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		log.Println(err)
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}
