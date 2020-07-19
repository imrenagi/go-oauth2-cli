APP_NAME=authcli

.PHONY: build.binaries
build.binaries:
	CGO_ENABLED=0 go build -a -ldflags '${LDFLAGS}' -o ${APP_NAME} ./cmd/main.go
