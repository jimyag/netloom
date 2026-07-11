//go:build !linux || !cgo || !netloom_nfqueue

package main

import "fmt"

func newNFQueueDNSCapture(queueNum int) (dnsCapture, error) {
	return nil, fmt.Errorf("NFQUEUE capture for queue %d requires Linux cgo build with -tags netloom_nfqueue and libnetfilter_queue development headers", queueNum)
}
