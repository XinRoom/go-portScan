sed -i "s/deb.debian.org/repo.huaweicloud.com/g" /etc/apt/sources.list
sed -i "s/security.debian.org/repo.huaweicloud.com/g" /etc/apt/sources.list

apt update
apt install libpcap-dev gcc -y

export GOPROXY="https://goproxy.io,https://proxy.golang.org,direct"
export CGO_LDFLAGS="-Wl,-static -L/usr/lib/x86_64-linux-gnu/libpcap.a -lpcap -Wl,-Bdynamic `pkg-config --libs --cflags dbus-1`"
export GOENABLE=1
go build -trimpath -ldflags="-s -w" ./cmd/go-portScan.go