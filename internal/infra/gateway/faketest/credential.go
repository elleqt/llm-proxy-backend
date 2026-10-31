package faketest

import (
	"encoding/json"
	"fmt"
	"os"
)

// CredentialStorage models a vendor serializer that only knows its own fields.
// It deliberately has no metadata setter for gateway-owned routing settings.
type CredentialStorage struct {
	Fields map[string]any
}

func (storage *CredentialStorage) SaveTokenToFile(path string) error {
	data, err := json.Marshal(storage.Fields)
	if err != nil {
		return fmt.Errorf("faketest: encode credential: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("faketest: write credential: %w", err)
	}

	return nil
}
