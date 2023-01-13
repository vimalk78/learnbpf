package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang logwatcher ./bpf/logwatcher.bpc.c -- -I/usr/include/bpf -I.

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

func main() {
	fmt.Println("vim-go")
}
