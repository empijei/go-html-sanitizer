package match

import "unicode/utf8"

type trie struct {
	children map[rune]*trie
	final    bool
}

func (t *trie) insert(w string) {
	if len(w) == 0 {
		t.final = true
		return
	}
	r, size := utf8.DecodeRuneInString(w)
	if t.children == nil {
		t.children = map[rune]*trie{}
	}
	child := t.children[r]
	if child == nil {
		child = &trie{}
	}
	t.children[r] = child
	child.insert(w[size:])
}

func (t *trie) match(c *Cursor) bool {
	if c.Pos >= len(c.Data) {
		return t.final
	}
	r, size := c.Peek()
	child := t.children[r]
	if child == nil {
		return t.final
	}
	c.Advance(size)
	return child.match(c)
}
