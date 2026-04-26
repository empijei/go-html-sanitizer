# Go HTML sanitizer

A DOM-based Go HTML sanitizer. If you allow users to provide arbitrary inputs that
you render in your web page, you likely need this sanitizer.

# Overview

This sanitizer allows to declare policies that mutate user-provided HTML into trusted
markup that can safely be embedded into a web page.

The simplest way to use it is to leverage the builtin policies.

## Safe Markup Allowlist

```go
import "github.com/empijei/go-html-sanitizer/policies"

// The UserGeneratedContent policy comes with generally safe allowlists such as
// text formatting, table, images, but it will block all scripts, event handlers,
// dangerous tags and styles.
//
// It can be further modified if needed and it's safe for concurrent use.
var ugcp = policies.UserGeneratedContent()

func Sanitize(untrusted string)(trusted string){
	return ugcp.SanitizeString(inMisc)
}
```

Example user-generated content policy effects:

| Title                                                                   | Input                                                                                                   | Output                                                                                              |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Removes event handlers, adds privacy attributes                         | `<img src=x onerror=alert(1)></img>`                                                                    | `<img src="x" crossorigin="anonymous"/>`                                                            |
| Allows harmless tags                                                    | `<h1>Test</h1>`                                                                                         | `<h1>Test</h1>`                                                                                     |
| Balances tags                                                           | `<u>These tags <i> are not </u> balanced </i>`                                                          | `<u>These tags <i> are not </i></u><i> balanced </i>`                                               |
| Removes orphaned tags                                                   | `</div> This closing tag is orphaned...`                                                                | ` This closing tag is orphaned...`                                                                  |
| Strips duplicated attributes, adds security, privacy and SEO attributes | `<A href="https://usethis.com" href="malicious" onclick=alert(1)>duplicated attributes are invalid</a>` | `<a href="https://usethis.com" rel="nofollow noreferrer ugc">duplicated attributes are invalid</a>` |

It additionally removes all HTML comments, directives, invalid tags, etc...

## Strict Mode

The empty policy is the safest policy, and it blocks all tags and all markup:

```go
import "github.com/empijei/go-html-sanitizer/sanitize"

var policy = &sanitize.Policy{
    // Nothing is allowed
}

func Example(){
	got := policy.SanitizeString(`prefix <a href="javascript:void(0)">link text</a>`+
     ` suffix<!--comment-->`)
    fmt.Println(got) // prefix link text suffix
}
```

## Custom Policies

This module aims to provide a safe and simple to use library to sanitize HTML, but
advanced users might specify very expressive policies via the available API, which supports:

- custom URI sanitizers
- `style` attributes tokenization and allowlisting
- attribute list modifiers
- tag removers and replacers
- strict allowlists for tags that must appear with specific attributes

it also comes with its own library of greedy, fast matchers to avoid regular-expression gotchas.

```go
import "github.com/empijei/go-html-sanitizer/sanitize"

var policy = &sanitize.Policy{
	Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
		"a": { // Allow a
			"href": nil, // Allow a.href
			"rel": nil, // Allow a.rel
		},
	},
	URIs: policies.NewURIs(), // Allow safe URIs
	ModifyAttributes: map[sanitize.TagName][]sanitize.AttributeModifier{
		"a": {func(_ string, attrs *[]html.Attribute) {
			// Always add a.rel with value of nofollow.
			// To see how to only add when not present please read below.
			*attrs = append(*attrs, html.Attribute{
				Key: "rel", Val: "nofollow",
			})
		}},
	},
}

func Example(){
	got := policy.SanitizeString(`prefix <a href="/foo">link text</a> suffix`)
    fmt.Println(got) // prefix <a href="/foo" rel="nofollow">link text</a> suffix
}
```

Please consider taking a look at how the user generated content policy is implemented
and the policy tests to see the full API in action.

# Why use this module

Unlike other available sanitizers, it understands the DOM instead of just tokenizing
HTML as a string. This means that potentially broken or unbalanced inputs will still
yield correct HTML as an output, ruling out a broader spectrum of attack vectors due
to parsing differentials or early tag termination.

# Comparison

Since bluemonday is the most widely used HTML sanitizer, here is comparison of features
and performance.

## Features

| Feature                                                      | BlueMonday | Sanitize |
| ------------------------------------------------------------ | ---------- | -------- |
| Customizable policies                                        | ✅         | ✅       |
| Strips harmful attributes                                    | ✅         | ✅       |
| Strips harmful tags                                          | ✅         | ✅       |
| Adds security and privacy attributes                         | ✅         | ✅       |
| Customizable attribute modifiers                             | ❌         | ✅       |
| Balances tags                                                | ❌         | ✅       |
| Removes spurious tags                                        | ❌         | ✅       |
| Removes duplicated attributes                                | ❌         | ✅       |
| Removes invalid HTML tags (e.g. void elements with children) | ❌         | ✅       |
| Fast, unambiguous matchers                                   | ❌         | ✅       |
| Arbitrary Go code for policies                               | ❌         | ✅       |
| Style attribute tokenizer                                    | ❌         | ✅       |

## Performance

While Sanitize offers a safer, more customizable API that performs better with medium
and large inputs, bluemonday is slightly faster and uses slightly less memory
(albeit with more allocations) with small inputs.

Evaluated on a Apple M4 Pro CPU.

| Inputs | Size  |
| ------ | ----- |
| Large  | 14 MB |
| Medium | 14 KB |
| Small  | 1 KB  |

### Time per operation

| Input   | BlueMonday  | Sanitize    | Sanitize VS BlueMonday |
| ------- | ----------- | ----------- | ---------------------- |
| Large   | 215.6m ± 0% | 190.9m ± 1% | -11.46% (p=0.000 n=10) |
| Medium  | 149.9µ ± 1% | 136.3µ ± 1% | -9.07% (p=0.000 n=10)  |
| Small   | 12.33µ ± 1% | 12.78µ ± 1% | +3.62% (p=0.000 n=10)  |
| geomean | 735.9µ      | 692.7µ      | -5.86%                 |

### Bytes allocated per operation

| Input   | BlueMonday   | Sanitize      | Sanitize VS BlueMonday |
| ------- | ------------ | ------------- | ---------------------- |
| Large   | 145.8Mi ± 0% | 166.3Mi ± 0%  | +14.03% (p=0.000 n=10) |
| Medium  | 120.5Ki ± 0% | 145.0Ki ± 0%  | +20.37% (p=0.000 n=10) |
| Small   | 9.516Ki ± 0% | 18.167Ki ± 0% | +90.92% (p=0.000 n=10) |
| geomean | 555.3Ki      | 765.5Ki       | +37.87%                |

### Allocations per operation

| Input          | BlueMonday  | Sanitize    | Sanitize VS BlueMonday |
| -------------- | ----------- | ----------- | ---------------------- |
| Real/large-14  | 5.067M ± 0% | 1.901M ± 0% | -62.48% (p=0.000 n=10) |
| Real/medium-14 | 3.370k ± 0% | 1.382k ± 0% | -58.99% (p=0.000 n=10) |
| Real/small-14  | 304.0 ± 0%  | 176.0 ± 0%  | -42.11% (p=0.000 n=10) |
| geomean        | 17.32k      | 7.733k      | -55.34%                |

## Playground

This module comes with a playground (`go run ./playground`) that allows you to
experiment with your policy to see how it works, and compare it with tokenizer-based
sanitizers like bluemonday.

# Notes

As much as this sanitizer is fast and efficient, it's still **ALWAYS** suggested to
limit user input size to prevent DoS attacks.
