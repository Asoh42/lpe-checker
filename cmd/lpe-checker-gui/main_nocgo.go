//go:build !cgo

package main

import "fmt"

func main() {
	fmt.Println("lpe-checker GUI requires CGO/Fyne support. Rebuild with CGO_ENABLED=1 and platform GUI dependencies installed.")
}
