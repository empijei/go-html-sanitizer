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

	// Filter matches specific tags and attributes.
	Filter map[TagName]map[AttributeName]AttributeFilter

	// AttributeModifier allows to modify a slice of attributes for a node.
	AttributeModifier func(tag TagName, attrs *[]html.Attribute)

	// Modifier allows to modify tag attributes.
	Modifier map[TagName][]AttributeModifier
)

const (
	// AllTags allows to specify rules that apply to all tags.
	AllTags TagName = "*"
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
	// The special value [AllTags] can be used to allow attributes on all tags.
	//
	// Rules are applied after modifiers.
	Allow Filter
	// Must is like Allow, but the attributes are mandatory.
	//
	// Tags that appear here are implicitly allowed if and only if they have all
	// the attributes specified.
	Must Filter
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
	ModifyAttributes Modifier
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
	globAllow := p.Allow[AllTags]
	globModif := p.ModifyAttributes[AllTags]
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
		p.applyModifiers(globModif, tagName, n)
		p.filterAttributes(n, uris, tagName, globAllow, allowAttrs, mustAttrs)
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

func (p *Policy) applyModifiers(globModif []AttributeModifier, tagName string, n *html.Node) {
	for _, mod := range globModif {
		mod(tagName, &n.Attr)
	}
	mods, ok := p.ModifyAttributes[tagName]
	if ok {
		for _, mod := range mods {
			mod(tagName, &n.Attr)
		}
	}
}

var seenPool = mpool.New[string, struct{}]()

func (p *Policy) filterAttributes(n *html.Node, uris URIs, tagName string, globAllow, allowAttrs, mustAttrs map[AttributeName]AttributeFilter) {
	seen, release := seenPool.Get()
	defer release()
	filterAttributes(n, func(_ *html.Node, attr html.Attribute) (keep bool) {
		key := getKey(attr)
		if _, ok := seen[key]; ok {
			return false // duplicate attribute
		}
		seen[key] = struct{}{}

		if v, applies := uris.Validator(tagName, key); applies && !v(attr.Val) {
			return false
		}

		for _, allow := range []map[AttributeName]AttributeFilter{
			allowAttrs,
			mustAttrs,
			globAllow,
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

// Relax relaxes the filter so that everything that would be matched by either
// filters is now matched.
func (f *Filter) Relax(other Filter) {
	if (*f) == nil && other != nil {
		(*f) = Filter{}
	}
	for tag, otherAttributeMap := range other {
		pAttributeMap, ok := (*f)[tag]
		if !ok {
			(*f)[tag] = maps.Clone(otherAttributeMap)
			continue
		}
		orAttrMaps(pAttributeMap, otherAttributeMap)
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

// Restrict restricts the filter so that only things that would be matched by both
// filters are now matched.
func (f *Filter) Restrict(other Filter) {
	if f == nil {
		return
	}

	for tag, otherAttributeMap := range other {
		pAttributeMap, ok := (*f)[tag]
		if !ok {
			continue
		}
		andAttrMaps(pAttributeMap, otherAttributeMap)
	}
	for tag := range *f {
		_, ok := other[tag]
		if ok {
			continue
		}
		delete((*f), tag)
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

// Add inserts all the provided modifiers so that all are applied.
func (m *Modifier) Add(other Modifier) {
	if (*m) == nil && other != nil {
		(*m) = Modifier{}
	}
	for tag, otherModif := range other {
		pModif, ok := (*m)[tag]
		if !ok {
			(*m)[tag] = slices.Clone(otherModif)
			continue
		}
		(*m)[tag] = append(pModif, otherModif...)
	}
}
