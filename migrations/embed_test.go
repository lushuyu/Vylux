package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMigrationDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
	}{
		{name: "001_initial.sql", want: "0a62946e71b0db96c51f6e6a04fd2ebb84937324037116d754d3761a495f715f"},
		{name: "002_media_lifecycle.sql", want: "9f6e33126dc67e5309b2ccc7b41a1c29726172ed735634bad3cec1fcf9a3bdb7"},
		{name: "003_deployment_target.sql", want: "4c696946e2dfcdd9aabf2174ef37be47da0c5762fc8367d150a1e893930edd31"},
		{name: "004_stream_key_compatibility.sql", want: "eaa598e20456e538c90e3cce2099529a76cb0c632caec866b1af630ea91ac94e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents, err := FS.ReadFile(tt.name)
			if err != nil {
				t.Fatalf("read embedded migration: %v", err)
			}
			sum := sha256.Sum256(contents)
			if got := hex.EncodeToString(sum[:]); got != tt.want {
				t.Fatalf("migration digest = %s, want %s", got, tt.want)
			}
		})
	}
}
