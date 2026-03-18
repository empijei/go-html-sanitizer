package match

// Matcher is a function that potentially advances the cursor and returns whether the
// consumed data matches.
//
// If a matcher doesn't match, they can leave the cursor in an invalid state.
type Matcher = func(*Cursor) bool

// Check checks whether the matcher matches the given string.
func Check(m Matcher, in string) bool {
	c := Cursor{Data: in}
	return m(&c) && c.AtEnd()
}

// Combine combines a sequence of matchers.
func Combine(seq ...Matcher) Matcher {
	return func(c *Cursor) bool {
		for _, m := range seq {
			if !m(c) {
				return false
			}
		}
		return true
	}
}

// Or creates an alternative of matchers.
func Or(alt ...Matcher) Matcher {
	return func(c *Cursor) bool {
		back := c.Pos
		for _, m := range alt {
			if m(c) {
				return true
			}
			c.Pos = back // Reset and retry with the next.
		}
		return false
	}
}

// CombineOptSpace is like Combine but it accepts optional space between each match.
func CombineOptSpace(seq ...Matcher) Matcher {
	var ns []Matcher
	for _, m := range seq {
		ns = append(ns, OptSpace, m)
	}
	ns = append(ns, OptSpace)
	return Combine(ns...)
}
