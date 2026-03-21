package dom_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/empijei/sanitize/dom"
	"github.com/empijei/tst"
	"golang.org/x/net/html"
)

func TestEvict(t *testing.T) {
	check := func(t *testing.T, in, want string) {
		t.Helper()
		b := dom.NewBody()
		parsed := tst.Do(html.ParseFragment(strings.NewReader(in), b))(t)
		tst.Is(1, len(parsed), t)

		root := parsed[0]

		t.Log("Before removal:\n", render(root))
		for desc := range root.Descendants() {
			if len(desc.Attr) > 0 && desc.Attr[0].Val == "DELETE" {
				tst.No(dom.RemoveNode(desc), t)
			}
		}
		t.Log("After removal:\n", render(root))

		var buf strings.Builder
		tst.No(html.Render(&buf, root), t)
		got := buf.String()
		tst.Is(want, got, t)
	}
	t.Run("indent", func(t *testing.T) {
		doc := `<div id="a">
	<div id="b"></div>
	<div id="c"></div>
	<div id="DELETE">
		<div id="e"></div>
		<div id="f"></div>
	</div>
</div>`
		want := `<div id="a">
	<div id="b"></div>
	<div id="c"></div>
	
		<div id="e"></div>
		<div id="f"></div>
	
</div>`
		check(t, doc, want)
	})

	t.Run("childless", func(t *testing.T) {
		t.Run("first child", func(t *testing.T) {
			doc := `<div id="a"><div id="DELETE"></div>6</div>`
			want := `<div id="a">6</div>`
			check(t, doc, want)
		})
		t.Run("middle child", func(t *testing.T) {
			doc := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5<div id="DELETE"></div>6</div>`
			want := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>56</div>`
			check(t, doc, want)
		})
		t.Run("last child", func(t *testing.T) {
			doc := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5<div id="DELETE"></div></div>`
			want := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5</div>`
			check(t, doc, want)
		})
	})

	t.Run("with children", func(t *testing.T) {
		t.Run("first child", func(t *testing.T) {
			doc := `<div id="a"><div id="DELETE">6<div id="e">7</div>8<div id="f">9</div>10</div></div>`
			want := `<div id="a">6<div id="e">7</div>8<div id="f">9</div>10</div>`
			check(t, doc, want)
		})
		t.Run("middle child", func(t *testing.T) {
			doc := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5` +
				`<div id="DELETE">6<div id="e">7</div>8<div id="f">9</div>10</div>11</div>`
			want := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5` +
				`6<div id="e">7</div>8<div id="f">9</div>1011</div>`
			check(t, doc, want)
		})
		t.Run("last child", func(t *testing.T) {
			doc := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5` +
				`<div id="DELETE">6<div id="e">7</div>8<div id="f">9</div>10</div></div>`
			want := `<div id="a">1<div id="b">2</div>3<div id="c">4</div>5` +
				`6<div id="e">7</div>8<div id="f">9</div>10</div>`
			check(t, doc, want)
		})
	})
}

func render(n *html.Node) string {
	var sb strings.Builder
	renderStep(&sb, n, 0)
	return sb.String()
}

func renderStep(sb *strings.Builder, n *html.Node, lvl int) {
	for range lvl {
		sb.WriteRune('\t')
	}
	fmt.Fprintf(sb, "%v %q %v\n", n.Type.String(), n.Data, n.Attr)
	for ch := range n.ChildNodes() {
		renderStep(sb, ch, lvl+1)
	}
}
