package policies

import (
	"testing"

	"github.com/empijei/tst"
)

func TestMatchWXDescriptor(t *testing.T) {
	tst.Go(t)

	tst.Is(true, matchWidthOrDensityDescriptor("10w"), t)
	tst.Is(true, matchWidthOrDensityDescriptor("10x"), t)
	tst.Is(true, matchWidthOrDensityDescriptor("10.2x"), t)

	tst.Is(false, matchWidthOrDensityDescriptor("10.2w"), t)
	tst.Is(false, matchWidthOrDensityDescriptor("-10.2x"), t)
	tst.Is(false, matchWidthOrDensityDescriptor("-1w"), t)
	tst.Is(false, matchWidthOrDensityDescriptor("10r"), t)
}
