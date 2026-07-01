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

	if config.Telemetry.SockPath != "" {
		t.Errorf("sock-path should be empty by default")
	}

	if config.Telemetry.SockMode != "0660" {
		t.Errorf("sock-mode should be 0660 by default")
	}
}

func TestConfigGlobalCheck_TelemetrySockPath(t *testing.T) {
	tests := []struct {
		name       string
		sockPath   string
		sockMode   string
		tlsSupport bool
		wantErr    bool
	}{
		{
			name:       "sock-path and tls-support both set",
			sockPath:   "/run/dnscollector/telemetry.sock",
			sockMode:   "0660",
			tlsSupport: true,
			wantErr:    true,
		},
		{
			name:     "sock-path with invalid sock-mode",
			sockPath: "/run/dnscollector/telemetry.sock",
			sockMode: "not-an-octal",
			wantErr:  true,
		},
		{
			name:     "sock-path with valid sock-mode, no tls",
			sockPath: "/run/dnscollector/telemetry.sock",
			sockMode: "0600",
			wantErr:  false,
		},
		{
			name:    "defaults, no sock-path",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ConfigGlobal{}
			config.SetDefault()
			config.Telemetry.SockPath = tt.sockPath
			if tt.sockMode != "" {
				config.Telemetry.SockMode = tt.sockMode
			}
			config.Telemetry.TLSSupport = tt.tlsSupport

			err := config.Check(nil)
			if tt.wantErr && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
