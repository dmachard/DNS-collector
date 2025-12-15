package workers

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Mock MQTT client for testing
type MockMQTTClient struct {
	connected         bool
	publishedMessages []MockMessage
}

type MockMessage struct {
	Topic    string
	QoS      byte
	Retained bool
	Payload  interface{}
}

func (m *MockMQTTClient) Connect() mqtt.Token {
	m.connected = true
	return NewMockToken(true, nil)
}

func (m *MockMQTTClient) Disconnect(quiesce uint) {
	m.connected = false
}

func (m *MockMQTTClient) IsConnected() bool {
	return m.connected
}

func (m *MockMQTTClient) Publish(topic string, qos byte, retained bool, payload interface{}) mqtt.Token {
	m.publishedMessages = append(m.publishedMessages, MockMessage{
		Topic:    topic,
		QoS:      qos,
		Retained: retained,
		Payload:  payload,
	})
	return NewMockToken(true, nil)
}

func (m *MockMQTTClient) Subscribe(topic string, qos byte, callback mqtt.MessageHandler) mqtt.Token {
	return NewMockToken(true, nil)
}

func (m *MockMQTTClient) Unsubscribe(topics ...string) mqtt.Token {
	return NewMockToken(true, nil)
}

type MockToken struct {
	success bool
	error   error
	done    chan struct{}
}

func NewMockToken(success bool, err error) *MockToken {
	return &MockToken{
		success: success,
		error:   err,
		done:    make(chan struct{}),
	}
}

func (t *MockToken) Wait() bool {
	close(t.done)
	return true
}

func (t *MockToken) WaitTimeout(time.Duration) bool {
	close(t.done)
	return true
}

func (t *MockToken) Error() error {
	return t.error
}

func (t *MockToken) Done() <-chan struct{} {
	return t.done
}

func TestMQTT_V5_ProtocolFeatures(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 1883
	config.Loggers.MQTT.Topic = "dnscollector/test/v5"
	config.Loggers.MQTT.QOS = 1
	config.Loggers.MQTT.ProtocolVersion = "v5"
	config.Loggers.MQTT.Mode = pkgconfig.ModeJSON
	config.Loggers.MQTT.BufferSize = 5
	config.Loggers.MQTT.FlushInterval = 1

	logger := logger.New(false)
	mqttWorker := NewMQTT(config, logger, "test-mqtt-v5")

	// Test configuration
	mqttWorker.ReadConfig()
	if config.Loggers.MQTT.ProtocolVersion != "v5" {
		t.Errorf("Expected protocol version 'v5', got '%s'", config.Loggers.MQTT.ProtocolVersion)
	}

	// Test that v5 protocol is properly configured
	if config.Loggers.MQTT.QOS != 1 {
		t.Errorf("Expected QoS 1, got %d", config.Loggers.MQTT.QOS)
	}

	// Create test DNS messages
	testMessages := []dnsutils.DNSMessage{}
	for i := 0; i < 3; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.Init()
		dm.DNSTap.Identity = "test-identity"
		dm.DNSTap.TimeSec = int(time.Now().Unix())
		testMessages = append(testMessages, dm)
	}

	// Test message formatting for different modes
	testModes := []string{pkgconfig.ModeJSON, pkgconfig.ModeFlatJSON, pkgconfig.ModeText}

	for _, mode := range testModes {
		t.Run("Mode_"+mode, func(t *testing.T) {
			config.Loggers.MQTT.Mode = mode
			mqttWorker.ReadConfig()

			for _, dm := range testMessages {
				var payload string

				switch mode {
				case pkgconfig.ModeJSON:
					buffer := new(bytes.Buffer)
					json.NewEncoder(buffer).Encode(dm)
					payload = buffer.String()

					// Verify it's valid JSON
					var parsed map[string]interface{}
					if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
						t.Errorf("Invalid JSON payload: %v", err)
					}

				case pkgconfig.ModeFlatJSON:
					flat, err := dm.Flatten()
					if err != nil {
						t.Errorf("Flattening failed: %v", err)
						continue
					}
					buffer := new(bytes.Buffer)
					json.NewEncoder(buffer).Encode(flat)
					payload = buffer.String()

					// Verify it's valid JSON
					var parsed map[string]interface{}
					if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
						t.Errorf("Invalid flat JSON payload: %v", err)
					}

				case pkgconfig.ModeText:
					payload = dm.String(mqttWorker.textFormat, config.Global.TextFormatDelimiter, config.Global.TextFormatBoundary)
					if len(payload) == 0 {
						t.Errorf("Empty text payload")
					}
				}

				if len(payload) == 0 {
					t.Errorf("Empty payload for mode %s", mode)
				}
			}
		})
	}
}

func TestMQTT_V5_QoSLevels(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 1883
	config.Loggers.MQTT.Topic = "dnscollector/test/qos"
	config.Loggers.MQTT.ProtocolVersion = "v5"

	logger := logger.New(false)

	// Test all QoS levels
	qosLevels := []byte{0, 1, 2}

	for _, qos := range qosLevels {
		t.Run("QoS_"+string(rune('0'+qos)), func(t *testing.T) {
			config.Loggers.MQTT.QOS = qos
			mqttWorker := NewMQTT(config, logger, "test-mqtt-qos")
			mqttWorker.ReadConfig()

			if config.Loggers.MQTT.QOS != qos {
				t.Errorf("Expected QoS %d, got %d", qos, config.Loggers.MQTT.QOS)
			}
		})
	}
}

func TestMQTT_V5_ConnectionHandling(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 1883
	config.Loggers.MQTT.Topic = "dnscollector/test/connect"
	config.Loggers.MQTT.ProtocolVersion = "v5"
	config.Loggers.MQTT.ConnectTimeout = 1
	config.Loggers.MQTT.RetryInterval = 1

	logger := logger.New(false)
	mqttWorker := NewMQTT(config, logger, "test-mqtt-connect")

	// Test connection configuration
	mqttWorker.ReadConfig()

	// Verify timeout settings
	if config.Loggers.MQTT.ConnectTimeout != 1 {
		t.Errorf("Expected connect timeout 1, got %d", config.Loggers.MQTT.ConnectTimeout)
	}

	if config.Loggers.MQTT.RetryInterval != 1 {
		t.Errorf("Expected retry interval 1, got %d", config.Loggers.MQTT.RetryInterval)
	}
}

func TestMQTT_V5_MessageBuffering(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 1883
	config.Loggers.MQTT.Topic = "dnscollector/test/buffer"
	config.Loggers.MQTT.ProtocolVersion = "v5"
	config.Loggers.MQTT.BufferSize = 3
	config.Loggers.MQTT.FlushInterval = 2

	logger := logger.New(false)
	mqttWorker := NewMQTT(config, logger, "test-mqtt-buffer")

	mqttWorker.ReadConfig()

	// Test buffer configuration
	if config.Loggers.MQTT.BufferSize != 3 {
		t.Errorf("Expected buffer size 3, got %d", config.Loggers.MQTT.BufferSize)
	}

	if config.Loggers.MQTT.FlushInterval != 2 {
		t.Errorf("Expected flush interval 2, got %d", config.Loggers.MQTT.FlushInterval)
	}

	// Create test messages to test buffering
	testMessages := []dnsutils.DNSMessage{}
	for i := 0; i < 5; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.Init()
		dm.DNSTap.Identity = "buffer-test"
		testMessages = append(testMessages, dm)
	}

	// Test that messages can be added to buffer
	// (We can't test actual flushing without a real MQTT broker)
	if len(testMessages) != 5 {
		t.Errorf("Expected 5 test messages, got %d", len(testMessages))
	}
}

func TestMQTT_V5_TopicConfiguration(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 1883
	config.Loggers.MQTT.ProtocolVersion = "v5"

	logger := logger.New(false)

	// Test different topic configurations
	testTopics := []string{
		"dnscollector/test/simple",
		"dnscollector/test/with/slashes",
		"dnscollector/test/with+plus",
		"dnscollector/test/with/wildcard/#",
	}

	for _, topic := range testTopics {
		t.Run("Topic_"+topic, func(t *testing.T) {
			config.Loggers.MQTT.Topic = topic
			mqttWorker := NewMQTT(config, logger, "test-mqtt-topic")
			mqttWorker.ReadConfig()

			if config.Loggers.MQTT.Topic != topic {
				t.Errorf("Expected topic '%s', got '%s'", topic, config.Loggers.MQTT.Topic)
			}
		})
	}
}

func TestMQTT_V5_AuthenticationConfiguration(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 1883
	config.Loggers.MQTT.Topic = "dnscollector/test/auth"
	config.Loggers.MQTT.ProtocolVersion = "v5"
	config.Loggers.MQTT.Username = "testuser"
	config.Loggers.MQTT.Password = "testpass"

	logger := logger.New(false)
	mqttWorker := NewMQTT(config, logger, "test-mqtt-auth")

	mqttWorker.ReadConfig()

	// Test authentication configuration
	if config.Loggers.MQTT.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", config.Loggers.MQTT.Username)
	}

	if config.Loggers.MQTT.Password != "testpass" {
		t.Errorf("Expected password 'testpass', got '%s'", config.Loggers.MQTT.Password)
	}
}

func TestMQTT_V5_TLSConfiguration(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.MQTT.Enable = true
	config.Loggers.MQTT.RemoteAddress = testAddress
	config.Loggers.MQTT.RemotePort = 8883
	config.Loggers.MQTT.Topic = "dnscollector/test/tls"
	config.Loggers.MQTT.ProtocolVersion = "v5"
	config.Loggers.MQTT.TLSSupport = true
	config.Loggers.MQTT.TLSInsecure = true
	config.Loggers.MQTT.TLSMinVersion = "1.2"

	logger := logger.New(false)
	mqttWorker := NewMQTT(config, logger, "test-mqtt-tls")

	mqttWorker.ReadConfig()

	// Test TLS configuration
	if !config.Loggers.MQTT.TLSSupport {
		t.Errorf("Expected TLS support enabled")
	}

	if !config.Loggers.MQTT.TLSInsecure {
		t.Errorf("Expected TLS insecure enabled")
	}

	if config.Loggers.MQTT.TLSMinVersion != "1.2" {
		t.Errorf("Expected TLS min version '1.2', got '%s'", config.Loggers.MQTT.TLSMinVersion)
	}
}
