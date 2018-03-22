.PHONY: all test bench

test-v:
	go test ./... -v  -timeout=60000ms

test:
	go test ./...
	go test ./... -short -race
	go vet

bench: test
	go test ./... -test.run=NONE -test.bench=. -test.benchmem

get:
	go get

run: get
	go run

run-race: get
	go run -race

all: bench run
