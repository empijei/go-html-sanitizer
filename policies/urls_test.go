package policies

import (
	"testing"

	"github.com/empijei/go-html-sanitizer/sanitize"
	"github.com/empijei/tst"
)

func TestMatchWXDescriptor(t *testing.T) {
	tst.Go(t)

	tst.Is(true, matchWidthOrDensityDescriptor("10w"), t)
	tst.Is(true, matchWidthOrDensityDescriptor("10x"), t)
	tst.Is(true, matchWidthOrDensityDescriptor("10.2x"), t)

	tst.Is(false, matchWidthOrDensityDescriptor("10.2w"), t)
	tst.Is(false, matchWidthOrDensityDescriptor("-10.2x"), t)
	tst.Is(false, matchWidthOrDensityDescriptor("-1w"), t)
	tst.Is(false, matchWidthOrDensityDescriptor("10r"), t)
}

func TestURLs(t *testing.T) {
	tst.Go(t)
	in := `<a href="https://allowed.com/foo">link text</a>
<iframe src="https://frameable.com"></iframe>
<audio></audio>`
	up := NewURLs()
	p := sanitize.Policy{
		Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
			"a":      {"href": nil},
			"iframe": {"src": nil},
			"audio":  {"src": nil},
		},
	}
	up.Apply(&p)
	got := p.SanitizeString(in)
	want := ``
	tst.Is(want, got, t)
}
