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

// Step is a function that potentially consumes part of the string and returns
// the leftover string and whether the consumed data matches.
//
// If a step doesn't match, the returned remainder is considered invalid.
type Step func(string) (remainder string, ok bool)

// Matcher is a function that can match a full string.
type Matcher = func(input string) (match bool)

// Matcher returns a matcher for the step.
func (s Step) Matcher() Matcher {
	return func(input string) (match bool) {
		rem, ok := s(input)
		return ok && len(rem) == 0
	}
}

// Combine combines a sequence of matchers.
func Combine(seq ...Step) Step {
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
func Or(alt ...Step) Step {
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

// Opt creates a step that is like an optional s, meaning that if s doesn't match
// it rewinds the input and returns true.
func Opt(s Step) Step {
	return func(in string) (remainder string, ok bool) {
		rem, ok := s(in)
		if !ok {
			return in, true
		}
		return rem, true
	}
}

// CombineEager is like Combine, but it stops when the string is empty and the
// match was successful.
func CombineEager(seq ...Step) Step {
	return func(s string) (rem string, ok bool) {
		rem = s
		for _, m := range seq {
			rem, ok = m(rem)
			if !ok {
				return rem, false
			}
			if rem == "" {
				break
			}
		}
		return rem, true
	}
}

// CombineOptSpace is like Combine but it accepts optional space between each match.
func CombineOptSpace(seq ...Step) Step {
	var ns []Step
	for _, m := range seq {
		ns = append(ns, OptSpace(), m)
	}
	ns = append(ns, OptSpace())
	return Combine(ns...)
}

// Repeat returns a step that only matches if s matches at least min times (included)
// and at most max times (included).
func Repeat(min, max uint, s Step) Step {
	return func(in string) (remainder string, ok bool) {
		remainder = in
		for i := range max {
			var rem string
			rem, ok = s(remainder)
			if ok {
				remainder = rem
				continue
			}
			return remainder, i >= min
		}
		return remainder, true
	}
}
