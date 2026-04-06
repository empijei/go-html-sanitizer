// Package sanitize implements a DOM-based HTML sanitizer.
package sanitize

import (
	"bytes"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/empijei/go-html-sanitizer/internal/mpool"
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
	AttributeModifier func(tag TagName, attrs *[]html.Attribute)

	// StyleFilter allows to filter style attribute values.
	StyleFilter func(tag TagName, style StyleToken) (keep bool)
)

// URIs is a validator that checks whether the given tag/attribute combination is supposed
// to be a URI and, if so, returns the appropriate filter for it.
type URIs interface {
	Validator(tag TagName, attr AttributeName) (validator AttributeFilter, applies bool)
}

// Policy is a policy to sanitize HTML.
//
// TextNodes and ElementNodes are the only type of nodes that are kept.
//
// Once a policy is built, it's safe for concurrent use as long as its fields are
// not modified.
type Policy struct {
	// Allow is the tags allowlist. Adding tags and attributes here means that those
	// tags may appear with any (or none) of the specified attributes.
	//
	// If a tag appears with a nil value, it's allowed, but with no attributes.
	//
	// If an AttributeFilter doesn't match the given attribute, the whole attribute is removed.
	//
	// A nil AttributeFilter is treated like an allow-all.
	//
	// Rules are applied after modifiers.
	Allow map[TagName]map[AttributeName]AttributeFilter
	// Must is like Allow, but the attributes are mandatory.
	//
	// Tags that appear here are implicitly allowed if and only if they have all
	// the attributes specified.
	Must map[TagName]map[AttributeName]AttributeFilter
	// AllowGlobal is like Allow but applies to all tags that are present in Allow.
	AllowGlobal map[AttributeName]AttributeFilter
	// AllowStyleAttribute allows to filter style attribute values.
	//
	// It works like AllowGlobal for style attributes, but it provides a tokenizer
	// for CSS2. Users can still provide an Allow or AllowGlobal filter for styles,
	// but this is more convenient.
	AllowStyleAttribute StyleFilter
	// URIs is the policy applied to URIs.
	//
	// For an attribute that contains a URI value to be allowed, it needs to both
	// be allowed by Allow and pass the additional URI check.
	//
	// A nil policy will block all attributes that might contain a URI.
	URIs URIs
	// ModifyAttributes allows to modify attributes for nodes.
	//
	// Modify is executed before filters, so attributes that are added or modified
	// need to still be valid according to the policy.
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

var nopErrSink = func(string, error) {}

// Sanitize applies the policy to the given HTML reader.
//
// Errors are only returned if I/O fails. Sanitization never generates errors.
func (p *Policy) Sanitize(dst io.Writer, src io.Reader) error {
	return p.SanitizeInspect(dst, src, nopErrSink)
}

// SanitizeInspect is like Sanitize, but allows to pass an inspect function that
// collects potential sanitizer errors when they happen.
func (p *Policy) SanitizeInspect(dst io.Writer, src io.Reader, errSink func(msg string, err error)) error {
	defer func() {
		/*
			FIXME: put this back once we are done fuzzing
				if p := recover(); p != nil {
					errSink("panic in sanitize", fmt.Errorf("recovered panic: %v", p))
				}
		*/
	}()
	fr, err := parseInBody(src)
	if err != nil {
		errSink("parse", err)
		return nil
	}
	if err := p.sanitizeDOM(fr); err != nil {
		errSink("sanitize", err)
		return nil
	}
	var buf bytes.Buffer
	for desc := range fr.fakeRoot.ChildNodes() {
		if err := html.Render(&buf, desc); err != nil {
			errSink("render", err)
			return nil
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
		switch n.Type {
		case html.TextNode:
			continue // Text is always safe
		case html.ErrorNode, html.DocumentNode, html.CommentNode, html.DoctypeNode, html.RawNode:
			// Remove everything else, including comments.
			remove = append(remove, n)
			continue
		case html.ElementNode:
			// Run the sanitizer
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
		p.applyModifiers(tagName, n)
		p.modifyStyles(tagName, n)
		p.filterAttributes(n, uris, tagName, allowAttrs, mustAttrs)
		if mustTag && !p.checkMust(mustAttrs, n) {
			remove = append(remove, n)
			continue
		}
	}
	for _, r := range remove {
		if err := removeNode(r); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) modifyStyles(tagName string, n *html.Node) {
	var (
		style *html.Attribute
		pos   int
	)
	for i, a := range n.Attr {
		switch {
		case a.Key == "style":
			style = &(n.Attr[i])
			pos = i
		}
	}
	if style == nil {
		return
	}
	style.Val = serializeStyle(func(yield func(StyleToken) bool) {
		for tok := range tokenizeStyleAttr(style.Val) {
			if !p.AllowStyleAttribute(tagName, tok) {
				continue
			}
			if !yield(tok) {
				return
			}
		}
	})
	if style.Val == "" {
		n.Attr = slices.Delete(n.Attr, pos, pos+1)
	}
}

var mustAttrPool = mpool.New[AttributeName, AttributeFilter]()

func (*Policy) checkMust(mustAttrs map[AttributeName]AttributeFilter, n *html.Node) (keep bool) {
	mustAttrs, release := mustAttrPool.Clone(mustAttrs)
	defer release()
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

var seenPool = mpool.New[string, struct{}]()

func (p *Policy) filterAttributes(n *html.Node, uris URIs, tagName string, allowAttrs, mustAttrs map[AttributeName]AttributeFilter) {
	seen, release := seenPool.Get()
	defer release()
	filterAttributes(n, func(_ *html.Node, attr html.Attribute) (keep bool) {
		key := getKey(attr)
		if _, ok := seen[key]; ok {
			return false // duplicate attribute
		}
		seen[key] = struct{}{}

		if key == "style" && p.AllowStyleAttribute != nil {
			return true
		}

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
