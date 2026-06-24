package ovn

import (
	"context"
	"fmt"
	"time"
)

func (w *LibOVSDBTopologyWriter) HealthCheck(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	if w == nil || w.client == nil {
		return time.Since(start), fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return time.Since(start), err
	}
	if !w.client.Connected() {
		return time.Since(start), fmt.Errorf("OVN northbound libovsdb client is not connected")
	}
	if err := w.client.Echo(ctx); err != nil {
		return time.Since(start), fmt.Errorf("OVN northbound libovsdb echo: %w", err)
	}
	return time.Since(start), nil
}
