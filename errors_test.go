package sociable

import (
	"errors"
	"testing"
)

func TestAuthorizationError(t *testing.T) {
	t.Parallel()

	bare := &AuthorizationError{Code: "access_denied"}
	described := &AuthorizationError{Code: "invalid_scope", Description: "unknown scope"}

	if bare.Error() != "sociable: the provider refused: access_denied" {
		t.Errorf("bare = %q", bare.Error())
	}

	if described.Error() != "sociable: the provider refused: invalid_scope: unknown scope" {
		t.Errorf("described = %q", described.Error())
	}

	if !errors.Is(bare, ErrAuthorization) || !errors.Is(bare, ErrAccessDenied) {
		t.Error("access_denied should match both")
	}

	if !errors.Is(described, ErrAuthorization) || errors.Is(described, ErrAccessDenied) {
		t.Error("another code should match ErrAuthorization only")
	}

	if errors.Is(described, ErrExchange) {
		t.Error("matched an unrelated error")
	}
}
