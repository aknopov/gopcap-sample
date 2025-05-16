package set

type dummyT struct{}

var dummy dummyT

// Do-it-again Set
type Set[T comparable] struct {
	m map[T]struct{}
}

func New[T comparable](vals ...T) *Set[T] {
	ret := Set[T]{m: make(map[T]struct{})}

	for _, v := range vals {
		ret.m[v] = dummy
	}
	return &ret
}

func (s *Set[T]) Enum() map[T]struct{} {
	return s.m
}

func (s *Set[T]) Add(value T) {
	s.m[value] = dummy
}

func (s *Set[T]) Remove(value T) {
	delete(s.m, value)
}
func (s *Set[T]) Contains(value T) bool {
	_, ok := s.m[value]
	return ok
}

func (s *Set[T]) Size() int {
	return len(s.m)
}
