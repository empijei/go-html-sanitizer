package mpool

import (
	"maps"
	"sync"
)

type MapPool[K comparable, V any] struct {
	p *sync.Pool
}

func New[K comparable, V any]() MapPool[K, V] {
	return MapPool[K, V]{p: &sync.Pool{
		New: func() any {
			return map[K]V{}
		},
	}}
}

func (m MapPool[K, V]) Clone(src map[K]V) (clone map[K]V, release func()) {
	nm := m.p.Get().(map[K]V) //nolint: errcheck,forcetypeassert // Enforced by generics
	clear(nm)
	maps.Insert(nm, maps.All(src))
	return nm, func() { m.p.Put(nm) }
}
