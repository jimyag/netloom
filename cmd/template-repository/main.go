package main

import (
	"fmt"

	_ "github.com/jimmicro/version"
	"github.com/jimyag/template-repository/internal/hello"
)

func main() {
	fmt.Println(hello.Greet("world"))
}
