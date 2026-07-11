package ovn

import (
	"context"
	"fmt"
	"time"

	"github.com/ovn-kubernetes/libovsdb/client"
)

const (
	DefaultLibOVSDBReconnectInitialBackoff = 500 * time.Millisecond
	DefaultLibOVSDBReconnectMaxBackoff     = 10 * time.Second
	libovsdbReconnectConnectTimeout        = 5 * time.Second
)

func (w *LibOVSDBTopologyWriter) EnableHealthReconnect(initialBackoff, maxBackoff time.Duration) {
	if w == nil {
		return
	}
	if initialBackoff < 0 {
		initialBackoff = 0
	}
	if maxBackoff <= 0 {
		maxBackoff = initialBackoff
	}
	if maxBackoff < initialBackoff {
		maxBackoff = initialBackoff
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reconnectEnabled = true
	w.reconnectInitialBackoff = initialBackoff
	w.reconnectMaxBackoff = maxBackoff
	w.reconnectFailures = 0
	w.nextReconnect = time.Time{}
}

func (w *LibOVSDBTopologyWriter) SetHealthReconnectClientFactory(currentCloser func(), reconnect func(context.Context) (client.Client, func(), error)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.clientCloser = currentCloser
	w.reconnectClient = reconnect
}

func (w *LibOVSDBTopologyWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.clientCloser != nil {
		w.clientCloser()
		w.clientCloser = nil
		w.client = nil
		return
	}
	if w.client != nil {
		w.client.Disconnect()
		w.client.Close()
		w.client = nil
	}
}

func (w *LibOVSDBTopologyWriter) HealthCheck(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	if w == nil || w.client == nil {
		return time.Since(start), fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return time.Since(start), err
	}
	if !w.client.Connected() {
		if err := w.reconnectHealthClient(ctx, start, false); err != nil {
			return time.Since(start), err
		}
	}
	if err := w.echoHealthClient(ctx); err != nil {
		if reconnectErr := w.reconnectHealthClient(ctx, start, true); reconnectErr != nil {
			return time.Since(start), fmt.Errorf("OVN northbound libovsdb echo: %w; reconnect failed: %w", err, reconnectErr)
		}
		if retryErr := w.echoHealthClient(ctx); retryErr != nil {
			return time.Since(start), fmt.Errorf("OVN northbound libovsdb echo after reconnect: %w", retryErr)
		}
	}
	w.recordHealthReconnectSuccess()
	return time.Since(start), nil
}

func (w *LibOVSDBTopologyWriter) echoHealthClient(ctx context.Context) error {
	w.mu.Lock()
	echo := w.healthEcho
	client := w.client
	w.mu.Unlock()
	if client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if echo != nil {
		return echo(ctx, client)
	}
	return client.Echo(ctx)
}

func (w *LibOVSDBTopologyWriter) reconnectHealthClient(ctx context.Context, start time.Time, force bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !force && w.client.Connected() {
		return nil
	}
	if !w.reconnectEnabled {
		return fmt.Errorf("OVN northbound libovsdb client is not connected")
	}
	now := time.Now()
	if !w.nextReconnect.IsZero() && now.Before(w.nextReconnect) {
		return fmt.Errorf("OVN northbound libovsdb client is not connected; next reconnect after %s", w.nextReconnect.Format(time.RFC3339Nano))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.reconnectClient != nil {
		nextClient, nextClose, err := w.reconnectClient(ctx)
		if err != nil {
			w.recordHealthReconnectFailureLocked(now)
			return fmt.Errorf("reconnect OVN northbound libovsdb client after %s: %w", time.Since(start), err)
		}
		oldClose := w.clientCloser
		oldClient := w.client
		w.client = nextClient
		w.clientCloser = nextClose
		w.reconnectFailures = 0
		w.nextReconnect = time.Time{}
		if oldClose != nil {
			oldClose()
		} else if oldClient != nil {
			oldClient.Disconnect()
			oldClient.Close()
		}
		return nil
	}
	if force {
		w.client.Disconnect()
	}
	if err := w.client.Connect(ctx); err != nil {
		w.recordHealthReconnectFailureLocked(now)
		return fmt.Errorf("reconnect OVN northbound libovsdb client after %s: %w", time.Since(start), err)
	}
	if err := w.waitForHealthReconnectConnected(ctx); err != nil {
		w.client.Disconnect()
		w.recordHealthReconnectFailureLocked(now)
		return err
	}
	if _, err := w.client.MonitorAll(ctx); err != nil {
		w.client.Disconnect()
		w.recordHealthReconnectFailureLocked(now)
		return fmt.Errorf("monitor OVN northbound libovsdb client after reconnect: %w", err)
	}
	w.reconnectFailures = 0
	w.nextReconnect = time.Time{}
	return nil
}

func (w *LibOVSDBTopologyWriter) waitForHealthReconnectConnected(ctx context.Context) error {
	if w.client.Connected() {
		return nil
	}
	waitCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		waitCtx, cancel = context.WithTimeout(ctx, libovsdbReconnectConnectTimeout)
	}
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-ticker.C:
			if w.client.Connected() {
				return nil
			}
		}
	}
}

func (w *LibOVSDBTopologyWriter) recordHealthReconnectSuccess() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reconnectFailures = 0
	w.nextReconnect = time.Time{}
}

func (w *LibOVSDBTopologyWriter) recordHealthReconnectFailureLocked(now time.Time) {
	w.reconnectFailures++
	backoff := reconnectBackoff(w.reconnectInitialBackoff, w.reconnectMaxBackoff, w.reconnectFailures)
	w.nextReconnect = now.Add(backoff)
}

func reconnectBackoff(initialBackoff, maxBackoff time.Duration, failures int) time.Duration {
	if failures <= 0 || initialBackoff <= 0 {
		return 0
	}
	backoff := initialBackoff
	for i := 1; i < failures; i++ {
		if maxBackoff > 0 && backoff >= maxBackoff/2 {
			return maxBackoff
		}
		backoff *= 2
	}
	if maxBackoff > 0 && backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}
