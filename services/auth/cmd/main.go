package main

import (
	"fmt"
	"net"

	"github.com/ramyadmz/goauth/internal/auth"
	"github.com/ramyadmz/goauth/pkg/pb"
	"google.golang.org/grpc"
)

func main() {
	listener, err := net.Listen("tcp", ":5051")
	if err != nil {
		fmt.Printf("Failed to listen:%v", err)
		return
	}
	authService := &auth.UserAuthService{}
	serviceOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(auth.ValidationInterceptor),
	}
	srv := grpc.NewServer(serviceOpts...)
	pb.RegisterOAuthServiceServer(srv, authService)
	srv.Serve(listener)
	if err != nil {
		fmt.Printf("Failed to serve:%v", err)
		return
	}
}
