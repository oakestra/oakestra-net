clang -g -O2 -target bpf -c packetCounter.c -o packetCounter.o
go build -buildmode=plugin