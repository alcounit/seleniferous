package main

import (
	"os"

	"github.com/alcounit/seleniferous"
)

func main() {

	if err := seleniferous.Run(); err != nil {
		os.Exit(1)
	}

}
