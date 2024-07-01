mkdir -p build
clang -O2 -target bpf -emit-llvm -c proxy.c -o build/proxy.bc
clang -O2 -target bpf -emit-llvm -c masking.c -o build/masking.bc
llvm-link -o build/main.bc build/proxy.bc build/masking.bc
clang -O2 -target bpf -c build/main.bc -o proxy.o
rm -R build
go build -buildmode=plugin -gcflags "all=-N -l"