package vouch_test

import (
	"errors"
	"testing"

	"github.com/gonstruct/vouch"
)

func TestAESSealerRoundTrips(t *testing.T) {
	sealer, err := vouch.AESSealer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := sealer.Seal([]byte(`{"state":"s"}`))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sealer.Open(sealed)
	if err != nil || string(opened) != `{"state":"s"}` {
		t.Fatalf("round trip: %q %v", opened, err)
	}

	// Every seal is different, so two handshakes never look alike on the wire.
	again, _ := sealer.Seal([]byte(`{"state":"s"}`))
	if again == sealed {
		t.Error("the nonce is not random")
	}
}

func TestAESSealerRejectsTamperingAndOtherKeys(t *testing.T) {
	sealer, _ := vouch.AESSealer([]byte("0123456789abcdef0123456789abcdef"))
	other, _ := vouch.AESSealer([]byte("fedcba9876543210fedcba9876543210"))

	sealed, _ := sealer.Seal([]byte("secret"))

	for name, value := range map[string]string{
		"tampered":  sealed[:len(sealed)-2] + "zz",
		"truncated": sealed[:4],
		"garbage":   "not base64 at all!",
		"empty":     "",
	} {
		if _, err := sealer.Open(value); !errors.Is(err, vouch.ErrSealed) {
			t.Errorf("%s: expected ErrSealed, got %v", name, err)
		}
	}
	if _, err := other.Open(sealed); !errors.Is(err, vouch.ErrSealed) {
		t.Errorf("another key: expected ErrSealed, got %v", err)
	}
}

func TestAESSealerNeedsAValidKey(t *testing.T) {
	if _, err := vouch.AESSealer([]byte("short")); err == nil {
		t.Fatal("a five byte key should be refused")
	}
}
