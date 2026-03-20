package match

import (
	"strconv"
	"strings"
	"unicode"
)

// OptSpace consumes whitespace, always matches.
//
//	/[[:space:]]*/
func OptSpace(s string) (rem string, ok bool) {
	for {
		size, r := peek(s)
		if size == 0 || !unicode.IsSpace(r) {
			break
		}
		s = s[size:]
	}
	return s, true
}

// Integer consumes a number, only returns true if it was a number.
//
// It doesn't allow for decimal points, exponential notation or similar
// variations.
//
//	/(-|+)?\d+/
func Integer(s string) (rem string, ok bool) {
	adv, ok := readInt(s)
	return s[adv:], ok
}

func readInt(s string) (advance int, ok bool) {
	size, r := peek(s)
	if r == '-' || r == '+' {
		advance += size
	}
	for {
		size, r := peek(s[advance:])
		if size == 0 || r < '0' || r > '9' {
			break
		}
		ok = true
		advance += size
	}
	return advance, ok
}

// IntegerBetween is like [Integer], but only matches if the number is between the two values,
// edges included.
//
// Numbers that overflow are rejected.
func IntegerBetween(low, high int64) Matcher {
	return func(s string) (rem string, ok bool) {
		adv, ok := readInt(s)
		if !ok {
			return s, false
		}
		val, err := strconv.ParseInt(s[:adv], 10, 64)
		if err != nil {
			return s, false
		}
		return s[adv:], low <= val && val <= high
	}
}

// Words matches a set of fixed words.
//
//	/(word1|word2|word3)/
func Words(accept ...string) Matcher {
	var t trie
	for _, w := range accept {
		t.insert(w)
	}
	return func(s string) (rem string, ok bool) {
		adv, ok := t.match(s, 0)
		return s[adv:], ok
	}
}

// Exact matches exactly the given word.
//
//	/word/
func Exact(accept string) Matcher {
	return func(s string) (string, bool) {
		if !strings.HasPrefix(s, accept) {
			return s, false
		}
		return s[len(accept):], true
	}
}

// Any consume the rest of the input.
//
//	/.*/
func Any(_ string) (rem string, ok bool) {
	return "", true
}

// None only matches the empty string.
//
//	//
func None(s string) (rem string, ok bool) {
	return s, s == ""
}

// RunesFunc returns a matcher that consumes a sequence of runes that match at least
// one of the provided matcher.
//
// Returns false IFF none matched.
func RunesFunc(match ...func(r rune) bool) Matcher {
	return func(s string) (rem string, ok bool) {
		var adv int
		for {
			size, r := peek(s[adv:])
			var found bool
			for _, m := range match {
				if !m(r) {
					continue
				}
				found = true
				break
			}
			if !found {
				break
			}
			adv += size
		}
		return s[adv:], adv != 0
	}
}

var (
	// Letters returns whether the sequence is at least one Letter.
	//
	// 	/[\p{L}]+/
	Letters = RunesFunc(unicode.IsLetter)
	// Numbers returns whether the sequence is at least one number.
	//
	// 	/[\p{N}]+/
	Numbers = RunesFunc(unicode.IsNumber)
	// LettersAndNumbers returns whether the sequence is at least one number.
	// 	/[\p{N}\p{L}]+/
	LettersAndNumbers = RunesFunc(unicode.IsLetter, unicode.IsNumber)
)
