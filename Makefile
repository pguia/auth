.PHONY: proto clean build run test

# Ensure Go bin is in PATH
GOPATH := $(shell go env GOPATH)
PATH := $(GOPATH)/bin:$(PATH)
export PATH


proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/auth/v1/auth.proto

clean:
	rm -f api/proto/auth/v1/*.pb.go

build:
	go build -o bin/auth-server cmd/server/main.go

run:
	go run cmd/server/main.go

test:
	go test -v ./...

docker-build:
	docker build -t chassis/auth:latest .

install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest