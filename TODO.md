# Features

- [] Rewrite Rules
  - [] Map of tags to replace with space (could provide a simple derfault with https://html.spec.whatwg.org/multipage/dom.html#flow-content). This would be an improvement on https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AddSpaceWhenStrippingTag
  - [] https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AddTargetBlankToFullyQualifiedLinks
  - [] Add rel="noreferrer nofollow ugc" to all links https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowStandardURLs
  - [] Add empty sandbox attribute to iframes if they are allowed
  - [] Add crossorigin="anonymous" https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.RequireCrossOriginAnonymous
  - [] Rewrite IDs to not collide?
  - [] Rewrite src https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.RewriteSrc
- [] The concept of a policy with allowed tags and attrs, with methods:
  - [] Relax ("OR" two policies)
  - [] Restrict ("AND" two policies)
  - [] RestrictWhenSpecified ("AND" two policies, but only when the provided one actually has a rule for a tag)
- [] https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowDataAttributes
- [] https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowDataURIImages
- [] Allow Global

# Prebuilt policies

- Allow Lists
- Allow Images
- Allow Tables
- Allow Data URI images
- ValidateURLs (with optional allowRelative)
- Allow Standard URLs https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowStandardURLs

# Decisions

- Should we allow comments?
- What is this for https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowElementsContent
- Do we want a set of special rules to support stuff like AllowMatching?
- Do we need to change something to prevent prototype pollution?
- Tokenize CSS to allow `style` attributes allowlisting? (spec https://html.spec.whatwg.org/multipage/dom.html#the-style-attribute )
  - [] https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowStyles
  - [] https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy.AllowStyling
- I think we shouldn't have AllowUnsafe.
- Sanitize signature? `Sanitize(dst io.Writer, src io.Reader) error`?

# Checks

How does this behave?

Programmatically constructed trees are typically also 'well-formed', but it is possible to construct a tree that looks innocuous but, when rendered and re-parsed, results in a different tree. A simple example is that a solitary text node would become a tree containing <html>, <head> and <body> elements. Another example is that the programmatic equivalent of "a<head>b</head>c" becomes "<html><head><head/><body>abc</body></html>".

Does Render re-escape HTML entities?
