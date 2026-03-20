// Package match implements simple, linear matchers for strings.
//
// This package is like a simplified version of regexp in go syntax to help debugging
// and to reduce the chance for errors.
//
// Matchers do not perform backtracking and ambiguous patterns might lead to strings
// not being matched while an equivalent regexp would match, and that is intentional.
package match

import "unicode/utf8"

// peek reads the first rune in a string, like in a for loop.
func peek(s string) (size int, r rune) {
	r, size = utf8.DecodeRuneInString(s)
	return size, r
}

// Matcher is a function that potentially consumes part of the string and returns
// the leftover string and whether the consumed data matches.
//
// If a matcher doesn't match, the returned remainder is considered invalid.
type Matcher = func(string) (remainder string, ok bool)

// Check checks whether the matcher matches the full given string.
func Check(m Matcher, in string) bool {
	rem, ok := m(in)
	return ok && len(rem) == 0
}

// Combine combines a sequence of matchers.
func Combine(seq ...Matcher) Matcher {
	return func(s string) (rem string, ok bool) {
		rem = s
		for _, m := range seq {
			rem, ok = m(rem)
			if !ok {
				return rem, false
			}
		}
		return rem, true
	}
}

// Or creates an alternative of matchers.
func Or(alt ...Matcher) Matcher {
	return func(s string) (rem string, ok bool) {
		back := s
		for _, m := range alt {
			rem, ok := m(back)
			if ok {
				return rem, true
			}
		}
		return back, false
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
