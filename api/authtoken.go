package api

import (
	"context"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
)

var (
	headerAuthorize = "authorization"
)

func CreateToken(userName string) (tokenString string) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":      "lora-app-server",
		"aud":      "lora-app-server",
		"nbf":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
		"sub":      "user",
		"username": userName,
	})
	tokenString, err := token.SignedString([]byte("verysecret"))
	if err != nil {
		panic(err)
	}
	return tokenString
}

// AuthToekn 自定义认证
type AuthToekn struct {
	Token string
	Tsl   bool
}

func (c AuthToekn) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		headerAuthorize: c.Token,
	}, nil
}

func (c AuthToekn) RequireTransportSecurity() bool {
	return c.Tsl
	//return false
}

// Claims defines the struct containing the token claims.
type Claims struct {
	jwt.StandardClaims

	// Username defines the identity of the user.
	Username string `json:"username"`
}

// Step1. 从 context 的 metadata 中，取出 token

func getTokenFromContext(ctx context.Context) string {
	val := metautils.ExtractIncoming(ctx).Get(headerAuthorize)
	return val
}

func CheckAuth(ctx context.Context) (username string) {
	tokenStr := getTokenFromContext(ctx)
	if len(tokenStr) == 0 {
		panic("get token from context error")
	}

	var clientClaims Claims
	token, err := jwt.ParseWithClaims(tokenStr, &clientClaims, func(token *jwt.Token) (interface{}, error) {
		if token.Header["alg"] != "HS256" {
			panic("ErrInvalidAlgorithm")
		}
		return []byte("verysecret"), nil
	})
	if err != nil {
		panic("jwt parse error")
	}

	if !token.Valid {
		panic("ErrInvalidToken")
	}

	return clientClaims.Username
}
