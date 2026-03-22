package sanitize

import (
	"bytes"
	"io"
	"strings"

	"github.com/empijei/go-html-sanitizer/dom"
	"golang.org/x/net/html"
)

type (
	// TagName is a tag name (without the <>).
	//
	// It is the lowercase string representing the tag.
	TagName = string
	// AttributeName is an attribute name.
	//
	// If an attribute requires a namespace, it can be prefixed as "namespace:key".
	AttributeName = string

	// AttributeFilter is a function that can be used to decide whether to keep an
	// attribute.
	AttributeFilter func(attrValue string) (keep bool)

	// AttributeModifier allows to modify a slice of attributes for a node.
	AttributeModifier func(tagName string, attrs *[]html.Attribute)

	// Matcher is a function that matches strings.
	Matcher = func(s string) (ok bool)
)

// Policy is a policy to sanitize HTML.
//
// TextNodes and ElementNodes are the only type of nodes that are kept.
type Policy struct {
	// Allow is the tags allowlist.
	//
	// Tags that are not in this map are removed from the DOM, and their children
	// are promoted to be their siblings.
	//
	// If a tag appears with a nil value, it's allowed without attributes.
	//
	// If an AttributeFilter doesn't match the given attribute, the whole attribute is removed.
	//
	// A nil AttributeFilter is treated like an allow-all.
	Allow map[TagName]map[AttributeName]AttributeFilter
	// AllowGlobal is like Allow but applies to all tags that are present in Allow.
	//
	// A nil AttributeFilter is treated like an allow-all.
	AllowGlobal map[AttributeName]AttributeFilter
	// ModifyAttributes allows to modify attributes for nodes.
	//
	// Modify is executed before filters and DOES NOT imply Allow.
	ModifyAttributes map[TagName]AttributeModifier
	// Remove allows to optionally specify tags that should be completely removed,
	// including all their children.
	//
	// This overrides Allow.
	//
	// The tags are replaced with the specified string.
	Remove map[TagName]string
}

var errSink = func(msg string, _ error) error { _ = msg; return nil }

// Sanitize applies the policy to the given HTML reader.
//
// Errors are only returned if I/O fails. Sanitization never generates errors.
func (p *Policy) Sanitize(dst io.Writer, src io.Reader) error {
	fr, err := dom.ParseInBody(src)
	if err != nil {
		return errSink("parse", err)
	}
	if err := p.sanitizeDOM(fr); err != nil {
		return errSink("sanitize", err)
	}
	var buf bytes.Buffer
	for desc := range fr.FakeRoot.ChildNodes() {
		if err := html.Render(&buf, desc); err != nil {
			return errSink("render", err)
		}
	}
	_, err = io.Copy(dst, &buf)
	return err
}

// SanitizeBytes is like sanitize, but works on byte slices.
func (p *Policy) SanitizeBytes(in []byte) []byte {
	var sb bytes.Buffer
	_ = p.Sanitize(&sb, bytes.NewReader(in))
	return sb.Bytes()
}

// SanitizeString is like sanitize, but works on strings.
func (p *Policy) SanitizeString(in string) string {
	var sb strings.Builder
	_ = p.Sanitize(&sb, strings.NewReader(in))
	return sb.String()
}

func (p *Policy) sanitizeDOM(fr *dom.Fragment) error {
	var remove []*html.Node
	for n := range fr.FakeRoot.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		tagName := n.Data
		if replace, ok := p.Remove[tagName]; ok {
			replaceWithText(n, replace)
			continue
		}

		allowAttrs, allowedTag := p.Allow[tagName]
		if !allowedTag {
			remove = append(remove, n)
		}

		mod, ok := p.ModifyAttributes[tagName]
		if ok {
			mod(tagName, &n.Attr)
		}

		dom.FilterAttributes(n, func(_ *html.Node, attr html.Attribute) (keep bool) {
			key := attr.Key
			if attr.Namespace != "" {
				key = attr.Namespace + ":" + attr.Key
			}
			flt, ok := allowAttrs[key]
			if ok && (flt == nil || flt(attr.Val)) {
				return true
			}
			gflt, ok := p.AllowGlobal[key]
			return ok && gflt(attr.Val)
		})
	}
	for _, r := range remove {
		if err := dom.RemoveNode(r); err != nil {
			return err
		}
	}
	return nil
}

func replaceWithText(n *html.Node, text string) {
	// Detach children from DOM.
	for child := range n.ChildNodes() {
		child.Parent = nil
	}
	*n = html.Node{
		Parent:      n.Parent,
		PrevSibling: n.PrevSibling,
		NextSibling: n.NextSibling,
		Type:        html.TextNode,
		Data:        text,

		// Zero values, here for clarity.
		FirstChild: nil,
		LastChild:  nil,
		DataAtom:   0,
		Namespace:  "",
		Attr:       nil,
	}
}
