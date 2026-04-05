package policies_test

import (
	"strings"
	"testing"

	"github.com/empijei/go-html-sanitizer/policies"
	"github.com/empijei/go-html-sanitizer/sanitize"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/net/html"
)

var payloads = []string{
	`<a onblur="alert(secret)" href="http://www.google.com">Google</a>`,
	`<noscript><p title="</noscript><img src='http://evil.com/tracking.gif'>">text</p></noscript>`,
	`<noscript><p title="</noscript><img src='data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+'>">text</p></noscript>`,
	`<img src='data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+'>`,
	`"><script>alert(document.cookie)</script>`,
	`<script>alert(document.cookie)</script>`,
}

var ugc = policies.UserGeneratedContent()

func FuzzSanitizeIsStable(f *testing.F) {
	for _, p := range payloads {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, data string) {
		firstPass := ugc.SanitizeString(data)
		secondPass := ugc.SanitizeString(firstPass)
		if firstPass != secondPass {
			t.Errorf("\nInput:\n%q\n\nFirstPass:\n%q\n\nSecondPass:%q\n\n", data, firstPass, secondPass)
		}
	})
}

func FuzzSanitizeDoesntEmitScripts(f *testing.F) {
	for _, p := range payloads {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, data string) {
		sanitized := ugc.SanitizeString(data)
		n, err := html.Parse(strings.NewReader(sanitized))
		if err != nil {
			t.Errorf("Failed to parse sanitized input %q with error %v", sanitized, err)
		}
		if checkForScriptTags(n) {
			t.Errorf("Sanitized input %q contains script tags", sanitized)
		}
		if checkForEventHandlers(n) {
			t.Errorf("Sanitized input %q contains event handlers", sanitized)
		}
	})
}

func checkForScriptTags(n *html.Node) bool {
	if n.Type == html.ElementNode && n.Data == "script" {
		return true
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if checkForScriptTags(c) {
			return true
		}
	}
	return false
}

func checkForEventHandlers(n *html.Node) bool {
	if n.Type == html.ElementNode {
		for _, attr := range n.Attr {
			if strings.HasPrefix(strings.ToLower(attr.Key), "on") {
				return true
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if checkForEventHandlers(c) {
			return true
		}
	}
	return false
}

// The following is substantially unusable.

var (
	bm          = bluemonday.UGCPolicy()
	ugcModified = policies.UserGeneratedContent()
)

func init() {
	uris := policies.NewURIs()
	uris.AllowSchemes["http"] = nil
	ugcModified.URIs = uris
	ugcModified.ModifyAttributes = map[sanitize.TagName][]sanitize.AttributeModifier{}
	policies.AddAttributeCrossOrigin(ugcModified)
	policies.AddAttributeRel(ugcModified, "nofollow", "noreferrer")

	bm.RequireNoReferrerOnLinks(true)
	bm.RequireNoFollowOnLinks(true)
	bm.RequireCrossOriginAnonymous(true)
}

func FuzzDifferential(f *testing.F) {
	f.Skip("These do two things that are too different to compare")
	for _, p := range payloads {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if strings.Contains(data, "<noscript>") {
			// Bugged
			return
		}
		t.Logf("Input: %q", data)
		gotBM := bm.Sanitize(parseRoundTrip(data))
		t.Logf("BM result: %q", gotBM)
		gotMPJ := ugcModified.SanitizeString(data)
		t.Logf("MP result: %q", gotMPJ)
		gotBMDOM, err := html.Parse(strings.NewReader(gotBM))
		if err != nil {
			t.Errorf("BM produced invalid HTML: %v", err)
		}
		gotMPJDOM, err := html.Parse(strings.NewReader(gotMPJ))
		if err != nil {
			t.Errorf("MP produced invalid HTML: %v", err)
		}
		if !nodesEqual(gotBMDOM, gotMPJDOM) {
			t.Errorf("DOMs differ")
		}
	})
}

var parsingContextBody = func() *html.Node {
	n, _ := html.Parse(strings.NewReader(`<html><head></head><body></body></html>`))
	return n.FirstChild.LastChild
}()

func parseRoundTrip(in string) string {
	children, err := html.ParseFragment(strings.NewReader(in), parsingContextBody)
	if err != nil {
		return in
	}
	var firstChild, lastChild *html.Node
	if len(children) > 0 {
		firstChild = children[0]
		lastChild = children[len(children)-1]
	}
	root := &html.Node{
		FirstChild: firstChild,
		LastChild:  lastChild,
	}
	for i, n := range children {
		n.Parent = root
		if i < len(children)-1 {
			n.NextSibling = children[i+1]
			children[i+1].PrevSibling = n
		}
	}

	var buf strings.Builder
	for desc := range root.ChildNodes() {
		if err := html.Render(&buf, desc); err != nil {
			panic(err)
		}
	}
	return buf.String()
}

func nodesEqual(n1, n2 *html.Node) bool {
	// If both are nil, they are equal
	if n1 == nil && n2 == nil {
		return true
	}
	// If only one is nil, they are not equal
	if n1 == nil || n2 == nil {
		return false
	}

	// 1. Compare Node Type (Element, Text, Comment, etc.)
	if n1.Type != n2.Type {
		return false
	}

	// 2. Compare Data (Tag name for Elements, content for Text/Comments)
	if n1.Data != n2.Data {
		return false
	}

	// 3. Compare Attributes (only relevant for ElementNodes)
	if !attributesEqual(n1.Attr, n2.Attr) {
		return false
	}

	// 4. Recursively compare children
	curr1 := n1.FirstChild
	curr2 := n2.FirstChild

	for {
		if curr1 == nil && curr2 == nil {
			break
		}
		// If one list of children is longer than the other
		if !nodesEqual(curr1, curr2) {
			return false
		}
		curr1 = curr1.NextSibling
		curr2 = curr2.NextSibling
	}

	return true
}

// attributesEqual checks if two slices of Attributes are identical.
// It accounts for the fact that attribute order might differ in some parsers.
func attributesEqual(attrs1, attrs2 []html.Attribute) bool {
	if len(attrs1) != len(attrs2) {
		return false
	}

	// Create a map for O(n) comparison
	attrMap := make(map[string]string)
	for _, a := range attrs1 {
		// Namespace is included to ensure uniqueness (e.g., xlink:href)
		key := a.Namespace + ":" + a.Key
		attrMap[key] = a.Val
	}

	for _, a := range attrs2 {
		key := a.Namespace + ":" + a.Key
		val, ok := attrMap[key]
		if !ok || val != a.Val {
			return false
		}
	}

	return true
}
