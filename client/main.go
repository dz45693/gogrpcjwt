package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"jwtdemo/api"

	"google.golang.org/grpc"
)

func main() {
	grpcCall()
	fmt.Println("http call.....")
	httpCall()
}

const (
	grpcPort = ":8080"
	httpPort = ":8080"
)

func grpcCall() {
	var conn *grpc.ClientConn
	//call Login
	conn, err := grpc.Dial(grpcPort, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()
	c := api.NewPingClient(conn)
	loginReply, err := c.Login(context.Background(), &api.LoginRequest{Username: "gavin", Password: "gavin"})
	if err != nil {
		log.Fatalf("Error when calling SayHello: %s", err)
	}
	//fmt.Println("Login Reply:", loginReply)

	//Call SayHello
	requestToken := new(api.AuthToekn)
	requestToken.Token = loginReply.Token
	conn, err = grpc.Dial(grpcPort, grpc.WithInsecure(), grpc.WithPerRPCCredentials(requestToken))
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()
	c = api.NewPingClient(conn)
	helloreply, err := c.SayHello(context.Background(), &api.PingMessage{Greeting: "foo"})
	if err != nil {
		log.Fatalf("Error when calling SayHello: %s", err)
	}
	log.Printf("Response from server: %s", helloreply.Greeting)
}

func httpCall() {
	urlpfx := "http://localhost" + httpPort
	//call login
	loginRequest := api.LoginRequest{Username: "gavin", Password: "gavin"}
	loginrequestByte, _ := json.Marshal(loginRequest)
	request, _ := http.NewRequest("POST", urlpfx+"/login", strings.NewReader(string(loginrequestByte)))
	request.Header.Set("Content-Type", "application/json")
	loginResponse, _ := http.DefaultClient.Do(request)
	loginReplyBytes, _ := ioutil.ReadAll(loginResponse.Body)
	defer loginResponse.Body.Close()
	var loginReply api.LoginReply
	json.Unmarshal(loginReplyBytes, &loginReply)
	//fmt.Println("token:" + loginReply.Token)

	///call say hello
	sayhelloRequest := api.PingMessage{Greeting: "gavin say "}
	sayhelloRequestByte, _ := json.Marshal(sayhelloRequest)
	request, _ = http.NewRequest("POST", urlpfx+"/sayhello", strings.NewReader(string(sayhelloRequestByte)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", loginReply.Token)
	sayhelloResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		fmt.Println(err)
	}
	sayhelloReplyBytes, err := ioutil.ReadAll(sayhelloResponse.Body)
	if err != nil {
		fmt.Println(err)
	}
	log.Printf(string(sayhelloReplyBytes))
}
