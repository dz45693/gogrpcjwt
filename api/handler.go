package api

import (
	"fmt"

	"golang.org/x/net/context"
)

// Server represents the gRPC server
type Server struct {
}

func (s *Server) Login(ctx context.Context, in *LoginRequest) (*LoginReply, error) {
	fmt.Println("Loginrequest: ", in.Username)
	if in.Username == "gavin" && in.Password == "gavin" {
		tokenString := CreateToken(in.Username)
		return &LoginReply{Status: "200", Token: tokenString}, nil

	} else {
		return &LoginReply{Status: "403", Token: ""}, nil
	}

}

// SayHello generates response to a Ping request
func (s *Server) SayHello(ctx context.Context, in *PingMessage) (*PingMessage, error) {
	msg := "bar"
	userName := CheckAuth(ctx)
	msg += " " + userName
	return &PingMessage{Greeting: msg}, nil
}
