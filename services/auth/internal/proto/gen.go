package proto

//go:generate protoc --go_out=../../pkg/pb --go_opt=paths=source_relative --go-grpc_out=../../pkg/pb --go-grpc_opt=paths=source_relative ./auth.proto
