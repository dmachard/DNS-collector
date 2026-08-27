package config

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
	// Check() runs against a defaults-only ConfigGlobal with the parsed YAML
	// passed as a map (see Config.IsValid -> Global.Check), so the telemetry
	// values must be validated from the map, not the struct. Drive the test the
	// same way the real config-load path does.
	tests := []struct {
		name      string
		telemetry map[string]interface{}
		wantErr   bool
	}{
		{
			name:      "sock-path and tls-support both set",
			telemetry: map[string]interface{}{"sock-path": "/run/dnscollector/telemetry.sock", "sock-mode": "0660", "tls-support": true},
			wantErr:   true,
		},
		{
			name:      "sock-path with invalid sock-mode",
			telemetry: map[string]interface{}{"sock-path": "/run/dnscollector/telemetry.sock", "sock-mode": "not-an-octal"},
			wantErr:   true,
		},
		{
			name:      "sock-path with valid sock-mode, no tls",
			telemetry: map[string]interface{}{"sock-path": "/run/dnscollector/telemetry.sock", "sock-mode": "0600"},
			wantErr:   false,
		},
		{
			name:      "no sock-path",
			telemetry: map[string]interface{}{"web-listen": "127.0.0.1:9165"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ConfigGlobal{}
			config.SetDefault()

			userCfg := map[string]interface{}{"telemetry": tt.telemetry}
			err := config.Check(userCfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
