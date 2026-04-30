package hello

import "fmt"

// Greet returns a greeting string for the given name.
func Greet(name string) string {
	return fmt.Sprintf("Hello, %s!", name)
}
