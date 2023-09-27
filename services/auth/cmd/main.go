package main

import (
	"fmt"
	"net"

	"github.com/ramyadmz/goauth/internal/service"
	"github.com/ramyadmz/goauth/pkg/pb"
	"google.golang.org/grpc"
)

func main() {
	listener, err := net.Listen("tcp", ":5051")
	if err != nil {
		fmt.Printf("Failed to listen:%v", err)
		return
	}
	authService := &service.AuthService{}
	serviceOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(service.ValidationInterceptor),
	}
	srv := grpc.NewServer(serviceOpts...)
	pb.RegisterAuthServiceServer(srv, authService)
	srv.Serve(listener)
	if err != nil {
		fmt.Printf("Failed to serve:%v", err)
		return
	}
}
