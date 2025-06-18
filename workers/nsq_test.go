package workers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type mockNSQProducer struct {
	published []publishedMessage
	stopped   bool
}

type publishedMessage struct {
	topic string
	body  []byte
}

func (m *mockNSQProducer) Publish(topic string, body []byte) error {
	m.published = append(m.published, publishedMessage{topic: topic, body: body})
	return nil
}

func (m *mockNSQProducer) Stop() {
	m.stopped = true
}

func createMockNsqClient(cfg *pkgconfig.Config, console *logger.Logger, name string) (*NsqClient, *mockNSQProducer) {
	client := NewNsqClient(cfg, console, name)
	mockProducer := &mockNSQProducer{}

	client.newProducer = func() (NSQProducer, error) {
		return mockProducer, nil
	}

	return client, mockProducer
}

func Test_NSQ_ClientAndPublishing(t *testing.T) {
	testTopic := "test-topic"
	cfg := pkgconfig.GetDefaultConfig()
	cfg.Loggers.Nsq.Topic = testTopic

	nsqClient, mockProducer := createMockNsqClient(cfg, logger.New(true), "test")

	if nsqClient == nil {
		t.Fatal("NSQ client should not be nil")
	}

	if mockProducer == nil {
		t.Fatal("Mock producer was not created")
	}

	if nsqClient.GetName() != "test" {
		t.Errorf("Expected name 'test', got %s", nsqClient.GetName())
	}

	// Start NSQ client
	done := make(chan bool)
	go func() {
		nsqClient.StartCollect()
		done <- true
	}()

	// Wait for client to start
	time.Sleep(100 * time.Millisecond)

	// Send a message to trigger publishing
	nsqClient.GetInputChannel() <- dnsutils.GetFakeDNSMessage()

	// Wait for message to be processed
	time.Sleep(200 * time.Millisecond)

	// Stop NSQ client first to prevent race condition
	nsqClient.Stop()

	select {
	case <-done:
		t.Log("NSQ client started and stopped successfully")
	case <-time.After(2 * time.Second):
		t.Fatal("NSQ client did not stop in time")
	}

	// Now verify message was published to mock producer (after NSQ client stopped)
	if len(mockProducer.published) != 1 {
		t.Fatalf("Expected 1 published message, got %d", len(mockProducer.published))
	}

	publishedMsg := mockProducer.published[0]
	if publishedMsg.topic != testTopic {
		t.Errorf("Expected topic %s, got %s", testTopic, publishedMsg.topic)
	}

	// Get the expected serialized version of the fake DNS message
	fakeDNSMessage := dnsutils.GetFakeDNSMessage()
	expectedMsg, err := json.Marshal(fakeDNSMessage)
	if err != nil {
		t.Fatalf("Failed to marshal fake DNS message: %v", err)
	}

	// Compare the published message with the expected serialized message
	if string(publishedMsg.body) != string(expectedMsg) {
		t.Errorf("Published message does not match expected serialized message.\nExpected: %s\nActual: %s", string(expectedMsg), string(publishedMsg.body))
	}

	if !mockProducer.stopped {
		t.Error("Mock producer was not stopped")
	}
}
