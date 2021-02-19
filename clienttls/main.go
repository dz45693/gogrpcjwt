package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"jwtdemo/api"

	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
	"github.com/uber/jaeger-lib/metrics"
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

	tracer, _ := TraceInit("GRPC-Client", "const", 1)
	tracerOptions := grpc.WithUnaryInterceptor(
		otgrpc.OpenTracingClientInterceptor(tracer, otgrpc.LogPayloads()),
	)

	//call Login
	conn, err := grpc.Dial("localhost"+port, grpc.WithTransportCredentials(creds), tracerOptions)
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
	conn, err = grpc.Dial(port, grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(requestToken), tracerOptions)
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

func TraceInit(serviceName string, samplerType string, samplerParam float64) (opentracing.Tracer, io.Closer) {
	cfg := &config.Configuration{
		ServiceName: serviceName,
		Sampler: &config.SamplerConfig{
			Type:  samplerType,
			Param: samplerParam,
		},
		Reporter: &config.ReporterConfig{
			LocalAgentHostPort: "192.168.100.21:6831",
			LogSpans:           true,
		},
	}

	tracer, closer, err := cfg.NewTracer(config.Logger(jaeger.StdLogger), config.Metrics(metrics.NullFactory))
	if err != nil {
		panic(fmt.Sprintf("Init failed: %v\n", err))
	}

	return tracer, closer
}
