package kerberos

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/logical"
	"github.com/ory/dockertest"
	"gopkg.in/ldap.v3"
)

func setupTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"keytab":          testValidKeytab,
		"service_account": "testuser",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
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

	data := map[string]interface{}{
		"authorization": "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}
	if !resp.IsError() && !strings.HasPrefix(resp.Error().Error(), "Missing or invalid authorization") {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}
}

func prepareLDAPAuthTestContainer(t *testing.T) (cleanup func(), retURL string) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	runOpts := &dockertest.RunOptions{
		Repository: "osixia/openldap",
		Tag:        "latest",
		Env: 		[]string{"LDAP_TLS=false"},
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