// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ory/dockertest/v3"
)

func setupTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"keytab":          testValidKeytab,
		"service_account": "testuser",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupTestBackend(t)

	cleanup, connURL := prepareLDAPTestContainer(t)
	defer cleanup()

	ldapReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ldapConfPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"url": connURL,
		},
	}

	resp, err := b.HandleRequest(context.Background(), ldapReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	data := map[string]interface{}{
		"authorization": "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: connURL,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || resp == nil || resp.IsError() {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	if e, ok := err.(logical.HTTPCodedError); !ok || e.Code() != 401 {
		t.Fatalf("no 401 thrown. err: %s resp: %#v\n", err, resp)
	}

	if headerVal, ok := resp.Headers["www-authenticate"]; ok {
		if strings.Compare(headerVal[0], "Negotiate") != 0 {
			t.Fatalf("www-authenticate not set to Negotiate. err: %s resp: %#v\n", err, resp)
		}
	} else {
		t.Fatalf("no www-authenticate header. err: %s resp: %#v\n", err, resp)
	}
}

func prepareLDAPTestContainer(t *testing.T) (cleanup func(), retURL string) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	runOpts := &dockertest.RunOptions{
		Repository: "osixia/openldap",
		Tag:        "latest",
		Env:        []string{"LDAP_TLS=false"},
	}
	resource, err := pool.RunWithOptions(runOpts)
	if err != nil {
		t.Fatalf("Could not start local MSSQL docker container: %s", err)
	}

	cleanup = func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	ldapAddr := fmt.Sprintf("localhost:%s", resource.GetPort("389/tcp"))
	retURL = "ldap://" + ldapAddr

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		conn, err := ldap.Dial("tcp", ldapAddr)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := conn.Bind("cn=admin,dc=example,dc=org", "admin"); err != nil {
			return err
		}

		searchRequest := ldap.NewSearchRequest(
			"dc=example,dc=org",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(&(objectClass=*))",
			[]string{"dn", "cn"},
			nil,
		)
		if _, err := conn.Search(searchRequest); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("Could not connect to ldap auth docker container: %s", err)
	}

	return
}

// TestLogin_TTLFieldAccepted validates that the login endpoint schema accepts
// the "ttl" field. This test cannot validate the actual TTL application because
// that requires successful SPNEGO authentication which needs a full Kerberos
// environment. The TTL parsing logic is thoroughly tested in TestParseTTL.
func TestLogin_TTLFieldAccepted(t *testing.T) {
	b, storage := setupTestBackend(t)

	cleanup, connURL := prepareLDAPTestContainer(t)
	defer cleanup()

	ldapReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ldapConfPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"url": connURL,
		},
	}

	resp, err := b.HandleRequest(context.Background(), ldapReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	// Test various TTL values to ensure the field is properly accepted in the schema
	testCases := []struct {
		name string
		ttl  string
	}{
		{"valid 5 minutes", "5m"},
		{"valid 1 hour", "1h"},
		{"valid 30 seconds", "30s"},
		{"valid complex duration", "1h30m"},
		{"empty string", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := map[string]interface{}{
				"authorization": "",
				"ttl":           tc.ttl,
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      data,
				Connection: &logical.Connection{
					RemoteAddr: connURL,
				},
			}

			resp, err = b.HandleRequest(context.Background(), req)
			// Will get 401 due to missing SPNEGO auth, but TTL field should be accepted
			// without any schema validation errors
			if err == nil || resp == nil || resp.IsError() {
				t.Fatalf("err: %s resp: %#v\n", err, resp)
			}

			if e, ok := err.(logical.HTTPCodedError); !ok || e.Code() != 401 {
				t.Fatalf("expected 401 error for ttl=%q, got: %s resp: %#v\n", tc.ttl, err, resp)
			}
		})
	}
}

// TestParseTTL thoroughly tests the TTL parsing logic. This is the core test
// for the dynamic TTL feature, validating all valid and invalid input formats.
func TestParseTTL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Empty and zero values
		{"empty string", "", 0, false},
		{"zero seconds", "0s", 0, false},
		{"zero minutes", "0m", 0, false},
		{"zero hours", "0h", 0, false},

		// Valid simple durations
		{"1 second", "1s", time.Second, false},
		{"30 seconds", "30s", 30 * time.Second, false},
		{"1 minute", "1m", time.Minute, false},
		{"5 minutes", "5m", 5 * time.Minute, false},
		{"1 hour", "1h", time.Hour, false},
		{"2 hours", "2h", 2 * time.Hour, false},
		{"24 hours", "24h", 24 * time.Hour, false},

		// Valid complex durations
		{"1h30m", "1h30m", 90 * time.Minute, false},
		{"2h30m45s", "2h30m45s", 2*time.Hour + 30*time.Minute + 45*time.Second, false},
		{"1m30s", "1m30s", 90 * time.Second, false},

		// Subsecond durations
		{"100 milliseconds", "100ms", 100 * time.Millisecond, false},
		{"1 microsecond", "1us", time.Microsecond, false},
		{"1 nanosecond", "1ns", time.Nanosecond, false},

		// Negative durations (Go time.ParseDuration supports these)
		{"negative 1 hour", "-1h", -time.Hour, false},
		{"negative 30 seconds", "-30s", -30 * time.Second, false},

		// Invalid formats
		{"invalid word", "invalid", 0, true},
		{"invalid unit", "1x", 0, true},
		{"missing number", "m", 0, true},
		{"just numbers", "123", 0, true},
		{"spaces", "1 h", 0, true},
		{"number with spaces", "1 hour", 0, true},
		{"double unit", "1mm", 0, true},
		{"special characters", "1h@", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTTL(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseTTL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.expected {
				t.Errorf("parseTTL(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
