#!/bin/sh

NS1="ns1"
NS2="ns2"

echo "Clean up..."
./clean.sh

echo "Build ebpf and go..."
rm -R build
mkdir -p build
clang -O2 -target bpf -emit-llvm -c proxy.c -o build/proxy.bc
clang -O2 -target bpf -emit-llvm -c masking.c -o build/masking.bc
llvm-link -o build/main.bc build/proxy.bc build/masking.bc
clang -O2 -target bpf -c build/main.bc -o build/main.o

clang -O2 -target bpf -c xdp_udp_count.c -o build/xdp_udp_count.o
# ip link set dev veth-ns2 xdp obj build/xdp_udp_count.o sec xdp
# ip link set dev veth-ns1 xdp obj build/xdp_udp_count.o sec xdp

cd loader
go build
cd ..

echo "Create environment..."
./env.sh

echo "Load and Attach ebpf..."
cd loader
./loader
cd ..

kill_processes() {
    echo "Caught SIGINT, terminating the Python processes..."
    kill $PID1
    exit 1
}

trap kill_processes SIGINT


echo "Exec server inside NS2..."
ip netns exec $NS2 python3 simple_server.py &
PID1=$!

echo "Exec client inside NS1..."
# ip netns exec $NS1 ping 142.250.184.3
ip netns exec $NS1 python3 simple_client.py
