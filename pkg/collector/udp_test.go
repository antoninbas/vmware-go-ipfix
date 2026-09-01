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
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testcerts "github.com/vmware/go-ipfix/pkg/test/certs"
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
		err := dtlsHandshake(context.Background(), stalledHandshaker{})
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, dtlsHandshakeTimeout, time.Since(start))
	})
}

// TestDTLSHandshakeCancelled checks that the handshake is aborted as soon as the parent
// context is done, without waiting for dtlsHandshakeTimeout.
func TestDTLSHandshakeCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		err := dtlsHandshake(ctx, stalledHandshaker{})
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, time.Duration(0), time.Since(start))
	})
}

func TestDTLSHandshakeCompleted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert.NoError(t, dtlsHandshake(context.Background(), immediateHandshaker{}))
		handshakeErr := errors.New("handshake failure")
		assert.ErrorIs(t, dtlsHandshake(context.Background(), immediateHandshaker{err: handshakeErr}), handshakeErr)
	})
}

// stopTimeout is how long we give Stop to return in the tests below. It is much smaller
// than dtlsHandshakeTimeout, so that a Stop which is only unblocked when the handshake
// times out is reported as a failure.
const stopTimeout = 5 * time.Second

func requireStops(t *testing.T, cp *CollectingProcess) {
	t.Helper()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		cp.Stop()
	}()
	select {
	case <-stopped:
	case <-time.After(stopTimeout):
		require.FailNow(t, "Collecting process did not stop", "Stop did not return after %v", stopTimeout)
	}
}

// TestDTLSCollectingProcessStopWithoutClient checks that the collecting process can be
// stopped while it is waiting for a client to connect.
func TestDTLSCollectingProcessStopWithoutClient(t *testing.T) {
	input := getCollectorInput(udpTransport, true, false)
	cp, err := InitCollectingProcess(input)
	require.NoError(t, err)
	go cp.Start()
	waitForCollectorReady(t, cp)
	requireStops(t, cp)
}

// stallingPacketConn drops outgoing packets after the first maxWrites ones, which lets us
// simulate a client which starts a DTLS handshake and then stops responding. The first
// writes are needed for the collector to accept the connection and start the handshake:
// pion only accepts a connection after a valid ClientHello (with a cookie).
type stallingPacketConn struct {
	net.PacketConn
	maxWrites int
	writes    atomic.Int32
}

func (c *stallingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if int(c.writes.Add(1)) > c.maxWrites {
		// Pretend that the packet was sent.
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestDTLSCollectingProcessStopDuringHandshake checks that the collecting process can be
// stopped while a client is in the middle of a DTLS handshake.
func TestDTLSCollectingProcessStopDuringHandshake(t *testing.T) {
	input := getCollectorInput(udpTransport, true, false)
	cp, err := InitCollectingProcess(input)
	require.NoError(t, err)
	go cp.Start()
	waitForCollectorReady(t, cp)

	collectorAddr, err := net.ResolveUDPAddr("udp", cp.GetAddress().String())
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(testcerts.FakeCert2))
	pConn, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	defer pConn.Close()
	// 2 writes are enough for the collector to accept the connection: the ClientHello, and
	// the ClientHello with the cookie provided by the HelloVerifyRequest. Everything after
	// that is dropped, so the handshake never completes.
	stallingConn := &stallingPacketConn{PacketConn: pConn, maxWrites: 2}
	conn, err := dtls.ClientWithOptions(
		stallingConn, collectorAddr,
		dtls.WithRootCAs(roots),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	)
	require.NoError(t, err)
	defer conn.Close()
	// The handshake is expected to never complete: we run it in the background and ignore
	// the outcome.
	go conn.Handshake() //nolint:errcheck

	// Wait until the collector has started the handshake.
	require.Eventually(t, func() bool {
		return int(stallingConn.writes.Load()) > stallingConn.maxWrites
	}, 5*time.Second, 50*time.Millisecond, "Client never got a reply from the collector")

	requireStops(t, cp)
}

// TestUDPCollectingProcessStopWithoutClient checks that the collecting process can be
// stopped when no client has ever sent a message.
func TestUDPCollectingProcessStopWithoutClient(t *testing.T) {
	input := getCollectorInput(udpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	require.NoError(t, err)
	go cp.Start()
	waitForCollectorReady(t, cp)
	requireStops(t, cp)
}
