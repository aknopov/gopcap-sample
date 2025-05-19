package set

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSet(t *testing.T) {
	assertT := assert.New(t)

	s := New[string]()

	s.Add("Hello")
	assertT.Equal(1, s.Size())
	assertT.True(s.Contains("Hello"))

	s.Add("Hello")
	assertT.Equal(1, s.Size())
	assertT.True(s.Contains("Hello"))

	s.Add("World")
	assertT.Equal(2, s.Size())
	assertT.True(s.Contains("World"))

	s.Remove("Hello")
	assertT.Equal(1, s.Size())
	assertT.False(s.Contains("Hello"))
	assertT.True(s.Contains("World"))
}

func TestVarArg(t *testing.T) {
	assertT := assert.New(t)

	s := New("Hello", "Hello", "World")

	assertT.Equal(2, s.Size())
	assertT.True(s.Contains("Hello"))
	assertT.True(s.Contains("World"))
}

func TestEnum(t *testing.T) {
	assertT := assert.New(t)

	s := New[string]()
	s.Add("Hello")
	s.Add("World")

	words := make([]string, 0)
	for e := range s.Enum() {
		words = append(words, e)
	}

	assertT.ElementsMatch([]string{"Hello", "World"}, words)
}

func TestClear(t *testing.T) {
	assertT := assert.New(t)

	s := New("Hello", "World")
	assertT.Equal(2, s.Size())

	s.Clear()
	assertT.Equal(0, s.Size())
}

func TestString(t *testing.T) {
	assertT := assert.New(t)

	s := New("Hello", "World")

	assertT.Equal("[Hello,World]", s.String())

}