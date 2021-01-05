package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"jwtdemo/api"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

const (
	port = ":8080"
)

func main() {
	// 創建grpc-gateway服務，轉發到grpc的9005端口
	gwmux := runtime.NewServeMux()
	opt := []grpc.DialOption{grpc.WithInsecure()}
	err := api.RegisterPingHandlerFromEndpoint(context.Background(), gwmux, "localhost"+port, opt)
	if err != nil {
		log.Fatal(err)
	}

	// 創建grpc服務
	rpcServer := grpc.NewServer()
	api.RegisterPingServer(rpcServer, new(api.Server))

	// 創建http服務，監聽9005端口，並調用上面的兩個服務來處理請求
	http.ListenAndServe(
		port,
		grpcHandlerFunc(rpcServer, gwmux),
	)
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
