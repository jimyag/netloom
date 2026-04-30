package hello_test

import (
	"testing"

	"github.com/jimyag/template-repository/internal/hello"
)

func TestGreet(t *testing.T) {
	got := hello.Greet("world")
	want := "Hello, world!"
	if got != want {
		t.Errorf("Greet() = %q, want %q", got, want)
	}
}
