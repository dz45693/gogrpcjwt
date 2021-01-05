package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"jwtdemo/api"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	grpcCall()
	fmt.Println("http call.....")
	httpCall()
}

const (
	port      = ":8283"
	clientPem = "../certs/server.pem"
	clientkey = "../certs/server.key"
	rootPem   = "../certs/ca.pem"
)

func grpcCall() {
	var conn *grpc.ClientConn
	cert, _ := tls.LoadX509KeyPair(clientPem, clientkey)
	certPool := x509.NewCertPool()
	ca, _ := ioutil.ReadFile(rootPem)
	certPool.AppendCertsFromPEM(ca)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
		RootCAs:      certPool,
	})
	//call Login
	conn, err := grpc.Dial("localhost"+port, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()
	//c := api.NewPingClient(conn)
	c := api.NewPingClient(conn)
	loginReply, err := c.Login(context.Background(), &api.LoginRequest{Username: "gavin", Password: "gavin"})
	if err != nil {
		log.Fatalf("Error when calling Login: %s", err)
	}
	//fmt.Println("Login Reply:", loginReply)

	//Call SayHello
	requestToken := new(api.AuthToekn)
	requestToken.Token = loginReply.Token
	requestToken.Tsl = true
	conn, err = grpc.Dial(port, grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(requestToken))
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
	urlpfx := "https://localhost" + port
	cert, _ := tls.LoadX509KeyPair(clientPem, clientkey)
	certPool := x509.NewCertPool()
	ca, _ := ioutil.ReadFile(rootPem)
	certPool.AppendCertsFromPEM(ca)

	t := &http2.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      certPool,
		},
	}
	httpClient := http.Client{Transport: t}
	//call login
	loginRequest := api.LoginRequest{Username: "gavin", Password: "gavin"}
	loginrequestByte, _ := json.Marshal(loginRequest)
	request, _ := http.NewRequest("POST", urlpfx+"/login", strings.NewReader(string(loginrequestByte)))
	request.Header.Set("Content-Type", "application/json")
	loginResponse, _ := httpClient.Do(request)
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
	sayhelloResponse, err := httpClient.Do(request)
	if err != nil {
		fmt.Println(err)
	}
	sayhelloReplyBytes, err := ioutil.ReadAll(sayhelloResponse.Body)
	if err != nil {
		fmt.Println(err)
	}
	log.Printf(string(sayhelloReplyBytes))
}
