package policies

import "github.com/empijei/go-html-sanitizer/sanitize"

// Strict returns a policy that removes all tags, leaving only text.
func Strict() *sanitize.Policy {
	return &sanitize.Policy{}
}
