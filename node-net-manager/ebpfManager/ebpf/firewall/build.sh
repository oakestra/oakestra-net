clang -g -O2 -target bpf -c firewall.c -o firewall.o
go build -buildmode=plugin -gcflags "all=-N -l"