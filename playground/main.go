// Package main implements a simple playground to test out the sanitizer.
package main

import (
	"context"
	_ "embed"
	"io"
	"net/http"
	"time"

	"github.com/empijei/go-html-sanitizer/policies"
	"github.com/empijei/srpc"
	"github.com/microcosm-cc/bluemonday"
)

//go:embed index.html
var indexHTML string

type Response struct {
	TookDOMUs    int64
	DOMSanitized string
	TOKSanitized string
	TookTOKUs    int64
}

var SanitizeEP = srpc.NewEndpointJSON[Response, string](http.MethodPost, "/api/sanitize.json")

func main() {
	bm := bluemonday.UGCPolicy()
	bm.RequireNoReferrerOnLinks(true)
	bm.RequireNoFollowOnLinks(true)
	bm.RequireCrossOriginAnonymous(true)
	bm.AddTargetBlankToFullyQualifiedLinks(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, indexHTML)
	})
	p := policies.UserGeneratedContent()
	SanitizeEP.Register(mux, func(_ context.Context, req string) (Response, error) {
		var resp Response

		start := time.Now()
		resp.DOMSanitized = p.SanitizeString(req)
		resp.TookDOMUs = time.Since(start).Microseconds()

		start = time.Now()
		resp.TOKSanitized = bm.Sanitize(req)
		resp.TookTOKUs = time.Since(start).Microseconds()

		return resp, nil
	})
	_ = http.ListenAndServe("localhost:8042", mux) //nolint: gosec // only used for local testing.
}
