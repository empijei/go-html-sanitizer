package dom_test

import (
	"strings"
	"testing"

	"github.com/empijei/sanitize/dom"
	"github.com/empijei/tst"
	"golang.org/x/net/html"
)

func FuzzRemoveNode(f *testing.F) {
	doc := `<div id="a">
	<div id="b"></div>
	<div id="c"></div>
	<div id="DELETE">
		<div id="e"></div>
		<div id="f"></div>
	</div>
</div>`
	f.Add(doc, byte(8))
	f.Fuzz(func(t *testing.T, in string, pos byte) {
		parsed, err := dom.ParseInBody(strings.NewReader(in))
		if err != nil {
			return
		}
		t.Logf("\npos: %v\ninput: %q\nrender:\n%v\n", pos%3, in, render(parsed.FakeRoot))

		for desc := range parsed.FakeRoot.Descendants() {
			if pos%3 == 0 && desc.Type == html.ElementNode {
				tst.No(dom.RemoveNode(desc), t)
			}
			pos--
		}
	})
}
