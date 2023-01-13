package main

import "fmt"

func main() {
	raw := []int{0, 1, 2, 3, 4, 5}
	fmt.Printf("%v\n", raw)
	raw = raw[len(raw)-2:]
	fmt.Printf("%v\n", raw)
}
