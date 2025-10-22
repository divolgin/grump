.PHONY: build
build:
	go build -o bin/grump ./cmd/grump

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: install
install:
	go install ./cmd/grump

