set GOENABLE=1
go build -trimpath -ldflags="-s -w" ./cmd/go-portScan.go