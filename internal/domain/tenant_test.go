package domain

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenant_TableName(t *testing.T) {
	tenant := Tenant{}
	assert.Equal(t, "tenants", tenant.TableName())
}

func TestTenant_IsActive_Active(t *testing.T) {
	tenant := Tenant{
		ID:     uuid.New(),
		Name:   "Test Tenant",
		Slug:   "test-tenant",
		Status: TenantStatusActive,
	}

	assert.True(t, tenant.IsActive())
}

func TestTenant_IsActive_Suspended(t *testing.T) {
	tenant := Tenant{
		ID:     uuid.New(),
		Name:   "Test Tenant",
		Slug:   "test-tenant",
		Status: TenantStatusSuspended,
	}

	assert.False(t, tenant.IsActive())
}

func TestTenant_IsActive_Pending(t *testing.T) {
	tenant := Tenant{
		ID:     uuid.New(),
		Name:   "Test Tenant",
		Slug:   "test-tenant",
		Status: TenantStatusPending,
	}

	assert.False(t, tenant.IsActive())
}

func TestTenant_Fields(t *testing.T) {
	id := uuid.New()
	settings := JSONMap{
		"feature_flags": map[string]interface{}{
			"mfa_required": true,
		},
	}

	tenant := Tenant{
		ID:       id,
		Name:     "Acme Corp",
		Slug:     "acme-corp",
		Status:   TenantStatusActive,
		Domain:   "acme.example.com",
		Settings: settings,
	}

	assert.Equal(t, id, tenant.ID)
	assert.Equal(t, "Acme Corp", tenant.Name)
	assert.Equal(t, "acme-corp", tenant.Slug)
	assert.Equal(t, TenantStatusActive, tenant.Status)
	assert.Equal(t, "acme.example.com", tenant.Domain)
	assert.NotNil(t, tenant.Settings)
}

// TenantStatus Constants Tests

func TestTenantStatus_Constants(t *testing.T) {
	assert.Equal(t, "active", string(TenantStatusActive))
	assert.Equal(t, "suspended", string(TenantStatusSuspended))
	assert.Equal(t, "pending", string(TenantStatusPending))
}

func TestTenant_WithSettings(t *testing.T) {
	tenant := Tenant{
		ID:       uuid.New(),
		Name:     "Test Tenant",
		Slug:     "test",
		Status:   TenantStatusActive,
		Settings: JSONMap{},
	}

	tenant.Settings["max_users"] = 100
	tenant.Settings["features"] = []string{"sso", "mfa"}

	assert.Equal(t, 100, tenant.Settings["max_users"])
	assert.Equal(t, []string{"sso", "mfa"}, tenant.Settings["features"])
}

func TestTenant_EmptyDomain(t *testing.T) {
	tenant := Tenant{
		ID:     uuid.New(),
		Name:   "Test Tenant",
		Slug:   "test",
		Status: TenantStatusActive,
		Domain: "", // Empty domain is valid
	}

	assert.Empty(t, tenant.Domain)
}

func TestJSONMap_Operations(t *testing.T) {
	jsonMap := JSONMap{}

	// Test empty map
	assert.Len(t, jsonMap, 0)

	// Add items
	jsonMap["string_key"] = "value"
	jsonMap["int_key"] = 123
	jsonMap["bool_key"] = true
	jsonMap["nested"] = map[string]interface{}{
		"inner_key": "inner_value",
	}

	assert.Len(t, jsonMap, 4)
	assert.Equal(t, "value", jsonMap["string_key"])
	assert.Equal(t, 123, jsonMap["int_key"])
	assert.Equal(t, true, jsonMap["bool_key"])

	nested := jsonMap["nested"].(map[string]interface{})
	assert.Equal(t, "inner_value", nested["inner_key"])
}

func TestJSONMap_Value(t *testing.T) {
	jsonMap := JSONMap{
		"key1": "value1",
		"key2": 123,
	}

	value, err := jsonMap.Value()
	require.NoError(t, err)
	require.NotNil(t, value)

	// Value should be JSON bytes
	bytes, ok := value.([]byte)
	require.True(t, ok)
	assert.Contains(t, string(bytes), "key1")
	assert.Contains(t, string(bytes), "value1")
}

func TestJSONMap_Value_Nil(t *testing.T) {
	var jsonMap JSONMap = nil

	value, err := jsonMap.Value()
	require.NoError(t, err)
	assert.Nil(t, value)
}

func TestJSONMap_Scan_Bytes(t *testing.T) {
	var jsonMap JSONMap
	input := []byte(`{"key1": "value1", "key2": 123}`)

	err := jsonMap.Scan(input)
	require.NoError(t, err)
	assert.Equal(t, "value1", jsonMap["key1"])
	assert.Equal(t, float64(123), jsonMap["key2"]) // JSON numbers are float64
}

func TestJSONMap_Scan_String(t *testing.T) {
	var jsonMap JSONMap
	input := `{"key1": "value1", "key2": 123}`

	err := jsonMap.Scan(input)
	require.NoError(t, err)
	assert.Equal(t, "value1", jsonMap["key1"])
	assert.Equal(t, float64(123), jsonMap["key2"])
}

func TestJSONMap_Scan_Nil(t *testing.T) {
	jsonMap := JSONMap{"existing": "value"}

	err := jsonMap.Scan(nil)
	require.NoError(t, err)
	assert.Nil(t, jsonMap)
}

func TestJSONMap_Scan_UnsupportedType(t *testing.T) {
	var jsonMap JSONMap

	err := jsonMap.Scan(12345) // unsupported type
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestJSONMap_Scan_InvalidJSON(t *testing.T) {
	var jsonMap JSONMap
	input := []byte(`{"invalid json`)

	err := jsonMap.Scan(input)
	assert.Error(t, err)
}

func TestJSONMap_RoundTrip(t *testing.T) {
	original := JSONMap{
		"string":  "hello",
		"number":  42.5,
		"boolean": true,
		"nested": map[string]interface{}{
			"inner": "value",
		},
	}

	// Serialize
	value, err := original.Value()
	require.NoError(t, err)

	// Deserialize
	var restored JSONMap
	err = restored.Scan(value)
	require.NoError(t, err)

	assert.Equal(t, "hello", restored["string"])
	assert.Equal(t, 42.5, restored["number"])
	assert.Equal(t, true, restored["boolean"])
}
