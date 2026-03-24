package match

// ASCIISet is a set of ASCII characters.
type ASCIISet [256]bool

var asciiLetters = func() *ASCIISet {
	var ret ASCIISet
	for b := 'a'; b <= 'z'; b++ {
		ret[b] = true
	}
	for b := 'A'; b <= 'Z'; b++ {
		ret[b] = true
	}
	return &ret
}()

var asciiNumbers = func() *ASCIISet {
	var ret ASCIISet
	for b := '0'; b <= '9'; b++ {
		ret[b] = true
	}
	return &ret
}()

var asciiLettersAndNumbers = func() *ASCIISet {
	l := ASCIISetLetters()
	l.Union(ASCIISetNumbers())
	return l
}

// ASCIISetLetters is the set of ASCII letters.
func ASCIISetLetters() *ASCIISet {
	ret := *asciiLetters
	return &ret
}

// ASCIISetNumbers is the set of ASCII Numbers.
func ASCIISetNumbers() *ASCIISet {
	ret := *asciiNumbers
	return &ret
}

// ASCIISetLettersAndNumbers is the set of ASCII letters and numbers.
func ASCIISetLettersAndNumbers() *ASCIISet {
	ret := *asciiLettersAndNumbers()
	return &ret
}

// ASCIIWhiteSpace is the set of ASCII whitespace characters.
func ASCIIWhiteSpace() *ASCIISet {
	return &ASCIISet{
		' ':  true,
		'\t': true,
		'\n': true,
		'\r': true,
		'\f': true,
		'\v': true,
	}
}

// ASCIISetFrom returns the set of the given chars.
func ASCIISetFrom(chars ...byte) *ASCIISet {
	var ret ASCIISet
	ret.Insert(chars...)
	return &ret
}

// Insert inserts the given values in the set.
func (a *ASCIISet) Insert(chars ...byte) *ASCIISet {
	for _, char := range chars {
		a[char] = true
	}
	return a
}

// Has returns whether b is in the set.
func (a *ASCIISet) Has(b byte) bool { return (*a)[b] }

// Union inserts all the values from other in the set.
func (a *ASCIISet) Union(other *ASCIISet) *ASCIISet {
	for char, has := range other {
		(*a)[char] = (*a)[char] || has
	}
	return a
}

// Negate inverts the match.
func (a *ASCIISet) Negate() *ASCIISet {
	for char, has := range *a {
		(*a)[char] = !has
	}
	return a
}

// Step returns a Step that matches the values in the set one or more times.
func (a *ASCIISet) Step() Step {
	return func(s string) (rem string, ok bool) {
		for {
			size, r := peek(s)
			if size != 1 || !a.Has(byte(r)) { //nolint: gosec // Checked.
				break
			}
			ok = true
			s = s[size:]
		}
		return s, ok
	}
}

// StepBetween returns a Step that matches between min and max times (both included).
func (a *ASCIISet) StepBetween(min, max int) Step {
	return func(s string) (rem string, ok bool) {
		for i := range max {
			size, r := peek(s)
			if size != 1 || !a.Has(byte(r)) {
				return s, i >= min
			}
			s = s[size:]
		}
		return s, true
	}
}
