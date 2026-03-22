// Package dom provides helpers to manipulate x/net/html DOM trees.
package dom

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

// parsingContextBody is the body of a simple HTML page, should not be modified,
// it's just available to be used as parsing context.
var parsingContextBody = func() *html.Node {
	n, _ := html.Parse(strings.NewReader(`<html><head></head><body></body></html>`))
	return n.FirstChild.LastChild
}()

// Fragment is a group of nodes parsed in a context.
type Fragment struct {
	// FakeRoot is an invalid html element that serves as a root for a set of children
	// resulting from parsing a fragment.
	FakeRoot *html.Node
}

// ParseInBody returns the result of parsing the given input as if it were in the
// context of a <body> tag.
func ParseInBody(in io.Reader) (*Fragment, error) {
	children, err := html.ParseFragment(in, parsingContextBody)
	if err != nil {
		return nil, fmt.Errorf("parse in body: %w", err)
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
			children[i].NextSibling = children[i+1]
			children[i+1].PrevSibling = children[i]
		}
	}
	return &Fragment{
		FakeRoot: root,
	}, nil
}

// ErrInvalidDOM is returned when a function of this package is called with an invalid DOM.
var ErrInvalidDOM = errors.New("invalid DOM")

// RemoveNode promotes the nodes children to be a the same level of the current node,
// and removes the node from the DOM.
//
// n MUST have a parent.
func RemoveNode(n *html.Node) error {
	if n.Parent == nil {
		return fmt.Errorf("%w: node must have a parent", ErrInvalidDOM)
	}
	defer func() {
		// Detach n from DOM
		n.Parent = nil
		n.PrevSibling = nil
		n.NextSibling = nil
		n.FirstChild = nil
		n.LastChild = nil
	}()

	// TODO(empijei): if this is too complex consider transforming this code to use
	// foreach n.ChildNodes() n.Parent.InsertBefore(child,n) + n.Parent.RemoveChild(n)
	// which would be slower but easier to maintain.

	// Make n children have n parent as parent
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		ch.Parent = n.Parent
	}

	if n.FirstChild == nil {
		if n.LastChild != nil {
			return fmt.Errorf("%w: node has first child but not last child", ErrInvalidDOM)
		}
		return reparentChildless(n)
	}
	return reparentWithChildren(n)
}

func reparentChildless(n *html.Node) error {
	switch {
	case n.Parent.FirstChild == n: // n is a first (or only) child
		n.Parent.FirstChild = n.NextSibling
		if n.NextSibling != nil {
			n.NextSibling.PrevSibling = nil
		}
		if n.Parent.LastChild == n { // n is an only child.
			n.Parent.LastChild = nil
		}
	case n.Parent.LastChild == n: // n is a last (but not the only) child
		if n.PrevSibling == nil {
			return fmt.Errorf("%w: last of many children doesn't have a prev sibling", ErrInvalidDOM)
		}
		n.PrevSibling.NextSibling = nil
		n.Parent.LastChild = n.PrevSibling
	default: // n is a middle child
		if n.PrevSibling == nil {
			return fmt.Errorf("%w: middle child doesn't have a prev sibling", ErrInvalidDOM)
		}
		if n.NextSibling == nil {
			return fmt.Errorf("%w: middle child doesn't have a next sibling", ErrInvalidDOM)
		}
		n.PrevSibling.NextSibling = n.NextSibling
		n.NextSibling.PrevSibling = n.PrevSibling
	}
	return nil
}

func reparentWithChildren(n *html.Node) error {
	switch {
	case n.Parent.FirstChild == n: // n is a first (or only) child
		n.Parent.FirstChild = n.FirstChild
		n.LastChild.NextSibling = n.NextSibling
		if n.NextSibling != nil {
			n.NextSibling.PrevSibling = n.LastChild
		}
		if n.Parent.LastChild == n { // n is an only child.
			n.Parent.LastChild = n.LastChild
		}
	case n.Parent.LastChild == n: // n is a last (not only) child
		if n.PrevSibling == nil {
			return fmt.Errorf("%w: last of many children doesn't have a prev sibling", ErrInvalidDOM)
		}
		n.PrevSibling.NextSibling = n.FirstChild
		n.FirstChild.PrevSibling = n.PrevSibling
		n.Parent.LastChild = n.LastChild
	default: // n is a middle child
		if n.PrevSibling == nil {
			return fmt.Errorf("%w: middle child doesn't have a prev sibling", ErrInvalidDOM)
		}
		if n.NextSibling == nil {
			return fmt.Errorf("%w: middle child doesn't have a next sibling", ErrInvalidDOM)
		}
		n.PrevSibling.NextSibling = n.FirstChild
		n.FirstChild.PrevSibling = n.PrevSibling
		n.NextSibling.PrevSibling = n.LastChild
		n.LastChild.NextSibling = n.NextSibling
	}
	return nil
}

// FilterAttributes only keeps the attributes that the filter function returns true for.
func FilterAttributes(n *html.Node, filter func(n *html.Node, attr html.Attribute) (keep bool)) {
	n.Attr = slices.DeleteFunc(n.Attr, func(attr html.Attribute) bool {
		return !filter(n, attr)
	})
}
