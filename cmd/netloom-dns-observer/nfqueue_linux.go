//go:build linux && cgo && netloom_nfqueue

package main

import (
	"context"
	"fmt"
	"sync"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"
)

type nfQueueDNSCapture struct {
	queueNum int
	queue    *nfqueue.Queue
}

func newNFQueueDNSCapture(queueNum int) (dnsCapture, error) {
	if queueNum < 0 {
		return nil, fmt.Errorf("-nfqueue must be non-negative")
	}
	queue := &nfqueue.Queue{}
	if err := queue.Init(); err != nil {
		return nil, fmt.Errorf("open NFQUEUE %d: %w", queueNum, err)
	}
	if err := queue.Bind(syscall.AF_INET); err != nil {
		queue.Close()
		return nil, fmt.Errorf("bind NFQUEUE %d IPv4: %w", queueNum, err)
	}
	if err := queue.Bind(syscall.AF_INET6); err != nil {
		_ = queue.Unbind(syscall.AF_INET)
		queue.Close()
		return nil, fmt.Errorf("bind NFQUEUE %d IPv6: %w", queueNum, err)
	}
	return &nfQueueDNSCapture{queueNum: queueNum, queue: queue}, nil
}

func (c *nfQueueDNSCapture) Close() error {
	if c == nil || c.queue == nil {
		return nil
	}
	_ = c.queue.DestroyQueue()
	_ = c.queue.Unbind(syscall.AF_INET)
	_ = c.queue.Unbind(syscall.AF_INET6)
	c.queue.Close()
	c.queue = nil
	return nil
}

func (c *nfQueueDNSCapture) Serve(ctx context.Context, observer dnsPacketObserver, maxPackets int) (result, error) {
	if c == nil || c.queue == nil {
		return result{}, fmt.Errorf("NFQUEUE capture is closed")
	}
	var mu sync.Mutex
	var out result
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			c.queue.StopLoop()
		})
	}
	if err := c.queue.SetCallback(func(payload *nfqueue.Payload) int {
		defer payload.SetVerdict(nfqueue.NF_ACCEPT)
		packet, ok := dnsResponseFromIPPacket(payload.Data)
		if !ok {
			return 0
		}
		records, written, err := observer.Observe(ctx, packet)
		if err != nil {
			return 0
		}
		mu.Lock()
		out.Packets++
		out.Records += records
		out.Written = written
		reached := maxPackets > 0 && out.Packets >= maxPackets
		mu.Unlock()
		if reached {
			stop()
		}
		return 0
	}); err != nil {
		return result{}, fmt.Errorf("set NFQUEUE %d callback: %w", c.queueNum, err)
	}
	if err := c.queue.CreateQueue(c.queueNum); err != nil {
		return result{}, fmt.Errorf("create NFQUEUE %d: %w", c.queueNum, err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	err := c.queue.Loop()
	close(done)
	mu.Lock()
	defer mu.Unlock()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if maxPackets > 0 && out.Packets >= maxPackets {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("read NFQUEUE %d: %w", c.queueNum, err)
	}
	return out, nil
}
