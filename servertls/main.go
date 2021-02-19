package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	api "jwtdemo/api"
	"log"
	"net/http"
	"strings"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
	"github.com/uber/jaeger-lib/metrics"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	port      = ":8283"
	serverPem = "../certs/server.pem"
	serverkey = "../certs/server.key"
	rootPem   = "../certs/ca.pem"
)

func main() {

	cert, _ := tls.LoadX509KeyPair(serverPem, serverkey)
	certPool := x509.NewCertPool()
	ca, _ := ioutil.ReadFile(rootPem)
	certPool.AppendCertsFromPEM(ca)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	})
	// 創建grpc-gateway服務，轉發到grpc的8080端口
	gwmux := runtime.NewServeMux()
	creds = credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	})
	opt := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	err := api.RegisterPingHandlerFromEndpoint(context.Background(), gwmux, "localhost"+port, opt)
	if err != nil {
		log.Fatal(err)
	}
	// 創建grpc服務
	//rpcServer := grpc.NewServer()
	tracer, _ := TraceInit("GRPC-Server", "const", 1)
	opts := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(
			api.AuthInterceptor,
			otgrpc.OpenTracingServerInterceptor(tracer, otgrpc.LogPayloads()),
		),
	}
	rpcServer := grpc.NewServer(opts...)
	api.RegisterPingServer(rpcServer, new(api.Server))

	// 創建http服務，監聽8080端口，並調用上面的兩個服務來處理請求
	http.ListenAndServeTLS(port, serverPem, serverkey, grpcHandlerFunc(rpcServer, gwmux))
}

// grpcHandlerFunc 根據請求頭判斷是grpc請求還是grpc-gateway請求
func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			allowCORS(otherHandler).ServeHTTP(w, r)
		}
	}), &http2.Server{})
}

func preflightHandler(w http.ResponseWriter, r *http.Request) {
	headers := []string{"Content-Type", "Accept", "Authorization"}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ","))
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE"}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	fmt.Println("preflight request for:", r.URL.Path)
	return
}

// allowCORS allows Cross Origin Resoruce Sharing from any origin.
// Don't do this without consideration in production systems.
func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
				preflightHandler(w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func getTLSConfig(host, caCertFile string, certOpt tls.ClientAuthType) *tls.Config {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool
	if certOpt > tls.RequestClientCert {
		caCert, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			fmt.Printf("Error opening cert file %s error: %v", caCertFile, err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	return &tls.Config{
		ServerName: host,
		ClientAuth: certOpt,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}

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
