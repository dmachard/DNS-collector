package workers

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"

	sarama "github.com/IBM/sarama"
)

const (
	testAddress = "127.0.0.1"
	testPort    = "49092"
	testTopic   = "dnscollector"
	// testUnreachableAddress = "198.51.100.1"
)

func createMockBroker(t *testing.T, brokerID int, address, topic string) (net.Listener, *sarama.MockBroker) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("Failed to create mock listener: %v", err)
	}

	broker := sarama.NewMockBrokerListener(t, int32(brokerID), listener)

	metadataResponse := sarama.NewMockMetadataResponse(t).
		SetBroker(broker.Addr(), broker.BrokerID()).
		SetController(broker.BrokerID())

	// 3 partitions for the topic
	metadataResponse.SetLeader(topic, 0, broker.BrokerID())
	metadataResponse.SetLeader(topic, 1, broker.BrokerID())
	metadataResponse.SetLeader(topic, 2, broker.BrokerID())

	broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t).SetApiKeys(
			[]sarama.ApiVersionsResponseKey{
				{ApiKey: 3, MinVersion: 0, MaxVersion: 6},
				{ApiKey: 0, MinVersion: 0, MaxVersion: 7},
			}),

		"MetadataRequest": metadataResponse,

		"ProduceRequest": sarama.NewMockProduceResponse(t).
			SetError(topic, 0, sarama.ErrNoError).
			SetVersion(6),
	})

	return listener, broker
}
func setupKafkaProducerConfig(address, port, topic, compress string) *pkgconfig.Config {
	cfg := pkgconfig.GetDefaultConfig()
	cfg.Loggers.KafkaProducer.BatchSize = 0
	cfg.Loggers.KafkaProducer.RemoteAddress = address
	portInt, _ := strconv.Atoi(port)
	cfg.Loggers.KafkaProducer.RemotePort = portInt
	cfg.Loggers.KafkaProducer.Topic = topic
	cfg.Loggers.KafkaProducer.Compression = compress
	cfg.Loggers.KafkaProducer.RetryInterval = 1
	cfg.Loggers.KafkaProducer.Partition = nil
	return cfg
}

// countProduceRequests counts how many times the broker received a ProduceRequest.
func countProduceRequests(broker *sarama.MockBroker) int {
	count := 0
	for _, req := range broker.History() {
		if _, ok := req.Request.(*sarama.ProduceRequest); ok {
			count++
		}
	}
	return count
}

func Test_KafkaProducer_Send(t *testing.T) {
	testcases := []struct {
		name     string
		compress string
	}{
		{"compress_none", "none"},
		{"compress_gzip", "gzip"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			listener, broker := createMockBroker(t, 1, testAddress+":"+testPort, testTopic)
			defer listener.Close()
			defer broker.Close()

			cfg := setupKafkaProducerConfig(testAddress, testPort, testTopic, tc.compress)
			producer := NewKafkaProducer(cfg, logger.New(true), "test")
			go producer.StartCollect()
			defer producer.StopLogger()

			time.Sleep(1 * time.Second)
			producer.GetInputChannel() <- dnsutils.GetFakeDNSMessage()
			time.Sleep(1 * time.Second)

			if count := countProduceRequests(broker); count == 0 {
				t.Fatal("No ProduceRequest received by broker")
			}
		})
	}
}

func Test_KafkaProducer_MultipleAddresses(t *testing.T) {
	addresses := []string{"localhost", "127.0.0.1"}

	// Start a mock broker on 127.0.0.1:9092
	listener, broker := createMockBroker(t, 1, addresses[0]+":"+testPort, testTopic)
	defer listener.Close()
	defer broker.Close()

	// Set RemoteAddress to multiple addresses
	cfg := setupKafkaProducerConfig(addresses[0]+","+addresses[1], testPort, testTopic, "none")
	producer := NewKafkaProducer(cfg, logger.New(true), "test")
	go producer.StartCollect()
	defer producer.StopLogger()

	time.Sleep(1 * time.Second)

	// Send a fake DNS message
	producer.GetInputChannel() <- dnsutils.GetFakeDNSMessage()
	time.Sleep(1 * time.Second)

	if count := countProduceRequests(broker); count == 0 {
		t.Fatal("No ProduceRequest received by broker with multiple addresses")
	}
}

func Test_KafkaProducer_Reconnect(t *testing.T) {
	// Initial broker setup
	listener1, broker1 := createMockBroker(t, 1, testAddress+":"+testPort, testTopic)
	time.Sleep(1 * time.Second)

	cfg := setupKafkaProducerConfig(testAddress, testPort, testTopic, "none")
	producer := NewKafkaProducer(cfg, logger.New(true), "test")
	go producer.StartCollect()
	defer producer.StopLogger()

	time.Sleep(1 * time.Second)
	producer.GetInputChannel() <- dnsutils.GetFakeDNSMessage()
	time.Sleep(1 * time.Second)

	if count := countProduceRequests(broker1); count == 0 {
		t.Fatal("No ProduceRequest received by broker")
	}

	// Simulate broker shutdown
	// Broker closed. Simulating downtime...
	fmt.Println("Broker closed. Simulating downtime...")
	broker1.Close()
	listener1.Close()
	time.Sleep(1 * time.Second)

	// Restart broker
	fmt.Println("Broker restarted. Waiting for reconnect...")
	listener2, broker2 := createMockBroker(t, 2, testAddress+":"+testPort, testTopic)
	defer listener2.Close()
	defer broker2.Close()
	time.Sleep(3 * time.Second)

	// Send another fake DNS message after reconnect
	producer.GetInputChannel() <- dnsutils.GetFakeDNSMessage()
	time.Sleep(3 * time.Second)
	producer.GetInputChannel() <- dnsutils.GetFakeDNSMessage()
	time.Sleep(3 * time.Second)

	// Verify that the new broker received ProduceRequests
	if count := countProduceRequests(broker2); count == 0 {
		t.Fatal("No ProduceRequest received by broker after reconnect")
	}
}
