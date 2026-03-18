package match

import "unicode/utf8"

// Cursor is a string with a cursor on it.
type Cursor struct {
	Pos  int
	Data string
}

// Peek returns the rune currently pointed by the cursor.
func (c *Cursor) Peek() (r rune, size int) {
	if c.Pos >= len(c.Data) {
		return 0, 0
	}
	return utf8.DecodeRuneInString(c.Data[c.Pos:])
}

// Advance advances the cursor.
//
// If 0 or a negative number is given, size is automatically computed for the next rune.
func (c *Cursor) Advance(size int) {
	if size <= 0 {
		_, size = utf8.DecodeRuneInString(c.Data[c.Pos:])
	}
	c.Pos += size
}

// Consume advances the cursor by count bytes and returns the consumed chunk.
//
// This might cause a rune to be split in half, so it's the caller responsibility
// to know how many bytes to consume. For a rune-by-rune operation use [*Cursor.Peek] and [*Cursor.Advance].
func (c *Cursor) Consume(count int) string {
	newPos := min(len(c.Data), c.Pos+count)
	ret := c.Data[c.Pos:newPos]
	c.Pos = newPos
	return ret
}

// AtEnd returns whether the cursor data has been fully consumed.
func (c *Cursor) AtEnd() bool {
	return c.Pos >= len(c.Data)
}
