package main

import (
	"fmt"
	"net"

	"github.com/ramyadmz/goauth/internal/service/user"
	"github.com/ramyadmz/goauth/pkg/pb"
	"google.golang.org/grpc"
)

func main() {
	listener, err := net.Listen("tcp", ":5051")
	if err != nil {
		fmt.Printf("Failed to listen:%v", err)
		return
	}
	authService := &user.UserAuthService{}
	serviceOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(user.ValidationInterceptor),
	}
	srv := grpc.NewServer(serviceOpts...)
	pb.RegisterUserAuthServiceServer(srv, authService)
	srv.Serve(listener)
	if err != nil {
		fmt.Printf("Failed to serve:%v", err)
		return
	}
}
