// Package dom provides helpers to manipulate x/net/html DOM trees.
package dom

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func NewBody() *html.Node {
	n, _ := html.Parse(strings.NewReader(`<html><head></head><body></body></html>`))
	return n.FirstChild.LastChild
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
