// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package status

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

type StatusTestSuite struct {
	config Configuration
}

var _ = Suite(&StatusTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *StatusTestSuite) SetUpTest(c *C) {
	s.config = Configuration{
		Interval:         10 * time.Millisecond,
		WarningThreshold: 20 * time.Millisecond,
		FailureThreshold: 80 * time.Millisecond,
	}
}

func (s *StatusTestSuite) TestCollectorStaleWarning(c *C) {
	var ok uint64

	m := []Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				time.Sleep(s.config.WarningThreshold * 2)
				return nil, nil
			},
			OnStatusUpdate: func(status Status) {
				if status.StaleWarning && status.Data == nil && status.Err != nil {
					atomic.AddUint64(&ok, 1)

				}
			},
		},
	}

	collector := NewCollector(m, s.config)
	defer collector.Close()

	// wait for the warning timeout to be reached twice
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&ok) >= 2
	}, 1*time.Second), IsNil)
}

func (s *StatusTestSuite) TestCollectorFailureTimeout(c *C) {
	var ok uint64

	m := []Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				time.Sleep(s.config.FailureThreshold * 2)
				return nil, nil
			},
			OnStatusUpdate: func(status Status) {
				if status.StaleWarning && status.Data == nil && status.Err != nil {
					atomic.AddUint64(&ok, 1)
				}
			},
		},
	}

	s.config.WarningThreshold = 10 * time.Second // to avoid hitting the warning threshold
	collector := NewCollector(m, s.config)
	defer collector.Close()

	// wait for the failure timeout to kick in
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&ok) >= 1
	}, 1*time.Second), IsNil)
}

func (s *StatusTestSuite) TestCollectorSuccess(c *C) {
	var ok uint64

	m := []Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				return "testData", nil
			},
			OnStatusUpdate: func(status Status) {
				if !status.StaleWarning && status.Data != nil && status.Err == nil {
					if s, isString := status.Data.(string); isString && s == "testData" {
						atomic.AddUint64(&ok, 1)
					}
				}
			},
		},
	}

	collector := NewCollector(m, s.config)
	defer collector.Close()

	// wait for the probe to succeed 3 times
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&ok) >= 3
	}, 1*time.Second), IsNil)
}
