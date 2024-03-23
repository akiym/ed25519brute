BUILD_LDFLAGS="-s -w"

.PHONY: build
build:
	go build -ldflags=$(BUILD_LDFLAGS)

.PHONY: install
install:
	go install -ldflags=$(BUILD_LDFLAGS)
