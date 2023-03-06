#!/bin/sh

set -x

if [ -e /.dockerenv ]; then
  sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories
  apk update
  apk add --no-cache linux-headers musl-dev gcc libpcap-dev mingw-w64-gcc
  export GOPROXY="https://goproxy.io,https://proxy.golang.org,direct"
  export CGO_ENABLED=1
  go get -u -d ./...

  for os in linux windows; do
    if [ $os = 'windows' ]; then
      ext='.exe'
      export CC=x86_64-w64-mingw32-gcc
      export CXX=x86_64-w64-mingw32-g++
    else
      ext=''
      export CC=gcc
      export CXX=g++
    fi
    GOOS=$os go build -trimpath -tags urfave_cli_no_docs -ldflags="-s -w -linkmode external --extldflags '-static'" -o go-portScan_$os$ext ./cmd/go-portScan.go
  done
  # It needs to run on a mac
  # GOOS=darwin go build -trimpath -ldflags="-s -w" -o go-portScan_darwin ./cmd/go-portScan.go
else
  docker run --rm -it -v `pwd`:/app -w /app golang:alpine sh ./build/build_static_alpine.sh
fi
