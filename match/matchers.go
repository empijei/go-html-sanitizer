package match

import (
	"strconv"
	"unicode"
)

// OptSpace consumes whitespace, always matches.
func OptSpace(c *Cursor) bool {
	for {
		r, size := c.Peek()
		if r != ' ' && r != '\t' {
			break
		}
		c.Advance(size)
	}
	return true
}

// Integer consumes a number, only returns true if it was a number.
//
// It doesn't allow for decimal points, exponential notation or similar
// variations.
func Integer(c *Cursor) bool {
	_, ok := readInt(c)
	return ok
}

// IntegerBetween is like [Integer], but only matches if the number is between the two values,
// edges included.
//
// Numbers that overflow are rejected.
func IntegerBetween(low, high int64) Matcher {
	return func(c *Cursor) bool {
		buf, ok := readInt(c)
		if !ok {
			return false
		}
		val, err := strconv.ParseInt(buf, 10, 64)
		if err != nil {
			return false
		}
		return low <= val && val <= high
	}
}

func readInt(c *Cursor) (buf string, ok bool) {
	start := c.Pos
	if r, size := c.Peek(); r == '-' || r == '+' {
		c.Advance(size)
	}
	for {
		r, size := c.Peek()
		if r < '0' || r > '9' {
			break
		}
		ok = true
		c.Advance(size)
	}
	return c.Data[start:c.Pos], ok
}

// Words matches a set of fixed words.
func Words(accept ...string) Matcher {
	// Extreme example: build a trie for matching speed.
	t := &trie{}
	for _, w := range accept {
		t.insert(w)
	}
	return func(c *Cursor) bool {
		return t.match(c)
	}
}

// Exact matches exactly the given word.
func Exact(accept string) Matcher {
	return func(c *Cursor) bool {
		return c.Consume(len(accept)) == accept
	}
}

// Any consume the rest of the input.
func Any(c *Cursor) bool {
	c.Pos = len(c.Data)
	return true
}

// None only matches the empty string.
func None(c *Cursor) bool {
	return c.Pos >= len(c.Data)
}

// ConsumeAll consumes all runes that match.
//
// Returns false IFF none matched.
func ConsumeAll(c *Cursor, match func(r rune) bool) bool {
	r, size := c.Peek()
	if !match(r) {
		return false
	}
	c.Advance(size)

	r, size = c.Peek()
	for size != 0 {
		if !match(r) {
			break
		}
		c.Advance(size)
		r, size = c.Peek()
	}
	return true
}

// Letters returns whether the sequence is at least one Letter.
func Letters(c *Cursor) bool {
	return ConsumeAll(c, unicode.IsLetter)
}

// Numbers returns whether the sequence is at least one number.
func Numbers(c *Cursor) bool {
	return ConsumeAll(c, unicode.IsNumber)
}

// LettersAndNumbers returns whether the sequence is at least one number.
func LettersAndNumbers(c *Cursor) bool {
	return ConsumeAll(c, func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsNumber(r)
	})
}
