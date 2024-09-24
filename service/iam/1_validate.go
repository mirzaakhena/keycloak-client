package iam

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func (kc *KeycloakClient) ValidateToken(tokenString string) (*jwt.Token, error) {
	publicKey, err := kc.PublicKeyCache.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		// If there's an error, invalidate the cache in case it's due to a key rotation
		kc.PublicKeyCache.InvalidateCache()
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Validate expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return nil, fmt.Errorf("token expired")
		}
		// Validate issuer
		expectedIssuer := fmt.Sprintf("%s/realms/%s", kc.KeycloakURL, kc.Realm)
		if claims["iss"] != expectedIssuer {
			return nil, fmt.Errorf("invalid issuer")
		}
		// Add more custom validations as needed
	} else {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}
