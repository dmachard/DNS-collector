package pkgconfig

import "testing"

func TestConfigGlobalSetDefault(t *testing.T) {
	// Create a ConfigGlobal instance
	config := ConfigGlobal{}

	// Call SetDefault to set default values
	config.SetDefault()

	if config.Trace.Verbose != false {
		t.Errorf("verbose mode should be disabled")
	}

	if config.PidFile != "" {
		t.Errorf("pidfile should be empty")
	}

	if config.Framestream.ControlFrameMaxLength != 4064 {
		t.Errorf("control-frame-max-length should be 4064")
	}

	if config.Framestream.DataFrameMaxLength != 65536 {
		t.Errorf("data-frame-max-length should be 65536")
	}

	if config.Framestream.HandshakeTimeout != 5 {
		t.Errorf("handshake-timeout should be 5")
	}

	if config.Framestream.ContentType != "protobuf:dnstap.Dnstap" {
		t.Errorf("content-type should be protobuf:dnstap.Dnstap")
	}
}
