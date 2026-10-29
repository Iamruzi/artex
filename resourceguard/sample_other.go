//go:build !linux && !windows

package resourceguard

import (
	"context"
	"fmt"
)

type unsupportedSampler struct{}

func NewSampler(string) Sampler { return unsupportedSampler{} }
func (unsupportedSampler) Sample(context.Context) (Sample, error) {
	return Sample{}, fmt.Errorf("资源保护采样目前支持 Linux / Windows；本平台停止自动派发")
}
