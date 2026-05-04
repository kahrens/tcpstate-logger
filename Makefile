BINARY := tcpstate-logger

.PHONY: all generate build run clean

all: generate build

generate: bpf/vmlinux.h
	go generate ./...

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

build: generate
	go build -o $(BINARY) .

run: build
	sudo ./$(BINARY) --insecure --stdout

clean:
	rm -f $(BINARY) bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o bpf/vmlinux.h
