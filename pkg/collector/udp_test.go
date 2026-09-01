// Copyright 2026 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

// stalledHandshaker simulates a client which starts a DTLS handshake and never completes
// it: it only returns when the provided context is done.
type stalledHandshaker struct{}

func (h stalledHandshaker) HandshakeContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// immediateHandshaker simulates a handshake which completes right away.
type immediateHandshaker struct {
	err error
}

func (h immediateHandshaker) HandshakeContext(ctx context.Context) error {
	return h.err
}

func TestDTLSHandshakeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		err := dtlsHandshake(stalledHandshaker{})
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, dtlsHandshakeTimeout, time.Since(start))
	})
}

func TestDTLSHandshakeCompleted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert.NoError(t, dtlsHandshake(immediateHandshaker{}))
		handshakeErr := errors.New("handshake failure")
		assert.ErrorIs(t, dtlsHandshake(immediateHandshaker{err: handshakeErr}), handshakeErr)
	})
}
