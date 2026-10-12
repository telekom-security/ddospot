.PHONY: test vet fuzz build
test: ; go test ./...
vet: ; go vet ./...
build: ; CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/ddospot ./cmd/ddospot
fuzz:
	for p in ./internal/ntp ./internal/ssdp ./internal/dns ./internal/chargen; do \
	  for f in $$(go test -list 'Fuzz.*' $$p | grep ^Fuzz); do go test -run=^$$ -fuzz=^$$f$$ -fuzztime=60s $$p || exit 1; done; done
