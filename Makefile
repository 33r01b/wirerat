.PHONY: build

all: build run

build:
	go build -o ./build/wirerat -v ./cmd/main.go

run:
	sudo ./build/wirerat