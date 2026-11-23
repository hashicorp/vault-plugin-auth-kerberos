// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

func TestCLI_RemoveInstanceName(t *testing.T) {
	type test struct {
		principalName string
		realm         string
		want          string
	}

	tests := []test{
		{principalName: "foobar/localhost", realm: "hashicorp.com", want: "foobar"},
		{principalName: "foobar/localhost/test", realm: "hashicorp.com", want: "foobar"},
		{principalName: "/localhost/test", realm: "hashicorp.com", want: ""},
	}

	for _, tc := range tests {
		kt := keytab.Keytab{}
		err := kt.AddEntry(tc.principalName, tc.realm, "password", time.Now(), 1, 17)
		if err != nil {
			t.Fatalf("got error adding entry, shouldn't have: %v", err)
		}

		removeInstanceNameFromKeytab(&kt)
		if kt.Entries[0].Principal.NumComponents != 1 {
			t.Fatalf("expected num components to be 1, got %d", kt.Entries[0].Principal.NumComponents)
		}

		if kt.Entries[0].Principal.Components[0] != tc.want {
			t.Fatalf("expected principal name to be %s, got %s", tc.want, kt.Entries[0].Principal.Components[0])
		}
	}
}

// TestCLIHandler_Help verifies that Help uses BinaryName in the commands it
// shows and falls back to "vault" when it's unset.
func TestCLIHandler_Help(t *testing.T) {
	t.Parallel()

	if help := (&CLIHandler{}).Help(); !strings.Contains(help, "vault login -method=kerberos") {
		t.Fatalf("expected help to use vault, got:\n%s", help)
	}

	help := (&CLIHandler{BinaryName: "vault-client"}).Help()
	if !strings.Contains(help, "vault-client login -method=kerberos") || strings.Contains(help, "vault login") {
		t.Fatalf("expected help to use vault-client, got:\n%s", help)
	}
}
