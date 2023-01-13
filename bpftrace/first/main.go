package main

import (
	"fmt"
	"os"
)

func main() {
	var err error
	f, err := os.OpenFile("/home/vimalkum/src/ebpf/learnbpf/bpftrace/first/junk.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
	if err != nil {
		fmt.Println(err)
		return
	}
	var t = 0
	defer func() { fmt.Printf("written %d bytes. err: %v\n", t, err) }()
	for c := 0; c < 10; c++ {
		n, err := fmt.Fprintf(f, "123\n")
		if err != nil {
			return
		}
		t += n
	}
}
