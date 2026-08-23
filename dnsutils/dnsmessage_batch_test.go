package dnsutils

import (
	"testing"
)

func TestDNSMessageBatch_AcquireAndRelease(t *testing.T) {
	batch := AcquireDNSMessageBatch(64)
	if batch == nil {
		t.Fatal("expected non-nil batch")
	}
	if batch.RefCount != 1 {
		t.Fatalf("expected RefCount=1, got %d", batch.RefCount)
	}
	if len(batch.Messages) != 0 {
		t.Fatalf("expected empty Messages slice, got len %d", len(batch.Messages))
	}
	if cap(batch.Messages) < 64 {
		t.Fatalf("expected cap >= 64, got %d", cap(batch.Messages))
	}

	dm := AcquireDNSMessage()
	dm.DNS.Qname = "example.com"
	batch.Messages = append(batch.Messages, dm)

	// Release batch should release contained DNSMessage back to pool
	batch.Release()
	if len(batch.Messages) != 0 {
		t.Fatalf("expected batch.Messages reset after Release, got %d", len(batch.Messages))
	}
}

func TestDNSMessageBatch_NewFromMessage(t *testing.T) {
	dm := AcquireDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"

	batch := NewDNSMessageBatchFromMessage(dm)
	if batch == nil {
		t.Fatal("expected non-nil batch")
	}
	if len(batch.Messages) != 1 {
		t.Fatalf("expected 1 message in batch, got %d", len(batch.Messages))
	}
	if batch.Messages[0].DNS.Qname != "dnscollector.dev" {
		t.Fatalf("unexpected qname: %s", batch.Messages[0].DNS.Qname)
	}

	batch.Release()
}

func TestDNSMessageBatch_RetainAndReleaseFanout(t *testing.T) {
	batch := AcquireDNSMessageBatch(10)
	dm := AcquireDNSMessage()
	batch.Messages = append(batch.Messages, dm)

	// Simulate fan-out to 3 consumers (initial RefCount=1 + Retain(2) = 3)
	batch.Retain(2)
	if batch.RefCount != 3 {
		t.Fatalf("expected RefCount=3, got %d", batch.RefCount)
	}

	// Consumer 1 releases
	batch.Release()
	if batch.RefCount != 2 {
		t.Fatalf("expected RefCount=2, got %d", batch.RefCount)
	}

	// Consumer 2 releases
	batch.Release()
	if batch.RefCount != 1 {
		t.Fatalf("expected RefCount=1, got %d", batch.RefCount)
	}

	// Consumer 3 releases (should trigger final release)
	batch.Release()
	if len(batch.Messages) != 0 {
		t.Fatalf("expected batch.Messages cleared on final release, got len %d", len(batch.Messages))
	}
}
