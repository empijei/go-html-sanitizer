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
)

//go:embed index.html
var indexHTML string

type Response struct {
	TookUs    int64
	Sanitized string
}

var SanitizeEP = srpc.NewEndpointJSON[Response, string](http.MethodPost, "/api/sanitize.json")

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, indexHTML)
	})
	p := policies.UserGeneratedContent()
	SanitizeEP.Register(mux, func(_ context.Context, req string) (Response, error) {
		start := time.Now()
		ret := p.SanitizeString(req)
		return Response{
			TookUs:    time.Since(start).Microseconds(),
			Sanitized: ret,
		}, nil
	})
	_ = http.ListenAndServe("localhost:8042", mux) //nolint: gosec // only used for local testing.
}
