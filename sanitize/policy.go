// Package sanitize implements a DOM-based HTML sanitizer.
package sanitize

import (
	"bytes"
	"io"
	"maps"
	"slices"
	"strings"

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

// URIs is a validator that checks whether the given tag/attribute combination is supposed
// to be a URI and, if so, returns the appropriate filter for it.
type URIs interface {
	Validator(tag TagName, attr AttributeName) (validator AttributeFilter, applies bool)
}

// Policy is a policy to sanitize HTML.
//
// TextNodes and ElementNodes are the only type of nodes that are kept.
type Policy struct {
	// Allow is the tags allowlist. Adding tags and attributes here means that those
	// tags may appear with any of the specified attributes.
	//
	// If a tag appears with a nil value, it's allowed without attributes.
	//
	// If an AttributeFilter doesn't match the given attribute, the whole attribute is removed.
	//
	// A nil AttributeFilter is treated like an allow-all.
	Allow map[TagName]map[AttributeName]AttributeFilter
	// Must is like Allow, but the attributes are mandatory.
	//
	// Tags that appear here are implicitly allowed if and only if they have all
	// the attributes specified.
	//
	// Must checks are performed before modifiers.
	Must map[TagName]map[AttributeName]AttributeFilter
	// AllowGlobal is like Allow but applies to all tags that are present in Allow.
	//
	// A nil AttributeFilter is treated like an allow-all.
	AllowGlobal map[AttributeName]AttributeFilter
	// URIs is the policy applied to URIs.
	//
	// For an attribute that contains a URI value to be allowed, it needs to both
	// be allowed by Allow and pass the additional URI check.
	//
	// A nil policy will block all attributes that might contain a URI.
	URIs URIs
	// ModifyAttributes allows to modify attributes for nodes.
	//
	// Modify is executed after filters, so attributes that are added or modified
	// by these functions are implicitly trusted.
	//
	// Modifers MUST NOT be nil.
	ModifyAttributes map[TagName][]AttributeModifier
	// Remove allows to optionally specify tags that should be completely removed,
	// including all their children.
	//
	// This overrides Allow.
	//
	// The tags are replaced with the specified (possibly empty) string.
	Remove map[TagName]string
}

var errSink = func(msg string, _ error) error { _ = msg; return nil }

// Sanitize applies the policy to the given HTML reader.
//
// Errors are only returned if I/O fails. Sanitization never generates errors.
func (p *Policy) Sanitize(dst io.Writer, src io.Reader) error {
	fr, err := parseInBody(src)
	if err != nil {
		return errSink("parse", err)
	}
	if err := p.sanitizeDOM(fr); err != nil {
		return errSink("sanitize", err)
	}
	var buf bytes.Buffer
	for desc := range fr.fakeRoot.ChildNodes() {
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

func (p *Policy) sanitizeDOM(fr *fragment) error {
	var remove []*html.Node
	uris := p.URIs
	if uris == nil {
		uris = defaultURIPolicy
	}
	for n := range fr.fakeRoot.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		tagName := n.Data
		if replace, ok := p.Remove[tagName]; ok {
			replaceWithText(n, replace)
			continue
		}

		mustAttrs, mustTag := p.Must[tagName]
		allowAttrs, allowedTag := p.Allow[tagName]
		if !allowedTag && !mustTag {
			remove = append(remove, n)
			continue
		}

		p.filterAttributes(n, uris, tagName, allowAttrs, mustAttrs)
		if mustTag && !p.checkMust(mustAttrs, n) {
			remove = append(remove, n)
			continue
		}
		p.applyModifiers(tagName, n)
	}
	for _, r := range remove {
		if err := removeNode(r); err != nil {
			return err
		}
	}
	return nil
}

func (*Policy) checkMust(mustAttrs map[AttributeName]AttributeFilter, n *html.Node) (keep bool) {
	mustAttrs = maps.Clone(mustAttrs)
	for _, attr := range n.Attr {
		key := getKey(attr)
		mflt, ok := mustAttrs[key]
		if !ok {
			continue
		}
		if mflt == nil || mflt(attr.Val) {
			delete(mustAttrs, key) // Passed the check
			continue
		}
		break
	}
	return len(mustAttrs) == 0 // All checks passed
}

func (p *Policy) applyModifiers(tagName string, n *html.Node) {
	mods, ok := p.ModifyAttributes[tagName]
	if ok {
		for _, mod := range mods {
			mod(tagName, &n.Attr)
		}
	}
}

func (p *Policy) filterAttributes(n *html.Node, uris URIs, tagName string, allowAttrs, mustAttrs map[AttributeName]AttributeFilter) {
	filterAttributes(n, func(_ *html.Node, attr html.Attribute) (keep bool) {
		key := getKey(attr)
		if v, applies := uris.Validator(tagName, key); applies && !v(attr.Val) {
			return false
		}

		for _, allow := range []map[AttributeName]AttributeFilter{
			allowAttrs,
			mustAttrs,
			p.AllowGlobal,
		} {
			flt, ok := allow[key]
			if ok && (flt == nil || flt(attr.Val)) {
				return true
			}
		}
		return false
	})
}

func getKey(attr html.Attribute) string {
	key := attr.Key
	if attr.Namespace != "" {
		return attr.Namespace + ":" + attr.Key
	}
	return key
}

// Relax modifies the policy so that all elements that would be allowed by either
// policy will now be allowed.
//
// Relax calls MergeModify.
//
// If there is a conflict on Remove, the existing one takes precedence.
func (p *Policy) Relax(other *Policy) {
	for tag, otherAttributeMap := range other.Allow {
		pAttributeMap, ok := p.Allow[tag]
		if !ok {
			p.Allow[tag] = maps.Clone(otherAttributeMap)
			continue
		}
		orAttrMaps(pAttributeMap, otherAttributeMap)
	}

	orAttrMaps(p.AllowGlobal, other.AllowGlobal)

	p.MergeModify(other.ModifyAttributes)

	for tag := range p.Remove {
		_, ok := other.Remove[tag]
		if !ok {
			delete(p.Remove, tag)
		}
	}
}

func orAttrMaps(this, other map[AttributeName]AttributeFilter) {
	for otherAttrName, otherFilter := range other {
		pFilter, ok := this[otherAttrName]
		if !ok || otherFilter == nil {
			this[otherAttrName] = otherFilter
			continue
		}
		if pFilter == nil {
			continue
		}
		// Both are not nil, OR them.
		this[otherAttrName] = func(attrValue string) (keep bool) {
			return pFilter(attrValue) || otherFilter(attrValue)
		}
	}
}

// Restrict modifies the policy so that all elements that would be allowed by both
// policies will now be allowed.
//
// Restrict calls MergeModify.
//
// If there is a conflict on Remove, the existing one takes precedence.
func (p *Policy) Restrict(other *Policy) {
	for tag, otherAttributeMap := range other.Allow {
		pAttributeMap, ok := p.Allow[tag]
		if !ok {
			continue
		}
		andAttrMaps(pAttributeMap, otherAttributeMap)
	}
	for tag := range p.Allow {
		_, ok := other.Allow[tag]
		if ok {
			continue
		}
		delete(p.Allow, tag)
	}

	andAttrMaps(p.AllowGlobal, other.AllowGlobal)

	p.MergeModify(other.ModifyAttributes)

	for tag, repl := range other.Remove {
		_, ok := p.Remove[tag]
		if !ok {
			p.Remove[tag] = repl
		}
	}
}

func andAttrMaps(this, other map[AttributeName]AttributeFilter) {
	for otherAttrName, otherFilter := range other {
		pFilter, ok := this[otherAttrName]
		if !ok || otherFilter == nil {
			continue
		}
		if pFilter == nil {
			this[otherAttrName] = otherFilter
		}
		// Both are not nil, AND them.
		this[otherAttrName] = func(attrValue string) (keep bool) {
			return pFilter(attrValue) && otherFilter(attrValue)
		}
	}
}

// MergeModify merges into the policy all the modifiers from the other policy.
func (p *Policy) MergeModify(other map[TagName][]AttributeModifier) {
	if other != nil && p.ModifyAttributes == nil {
		p.ModifyAttributes = map[TagName][]AttributeModifier{}
	}
	for tag, otherModif := range other {
		pModif, ok := p.ModifyAttributes[tag]
		if !ok {
			p.ModifyAttributes[tag] = slices.Clone(otherModif)
			continue
		}
		p.ModifyAttributes[tag] = append(pModif, otherModif...)
	}
}
