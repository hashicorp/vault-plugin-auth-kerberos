module github.com/hashicorp/vault-plugin-auth-kerberos

go 1.12

require (
	github.com/go-ldap/ldap/v3 v3.4.5
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/vault/api v1.9.2
	github.com/hashicorp/vault/sdk v0.9.2
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/lib/pq v1.2.0 // indirect
	github.com/ory/dockertest/v3 v3.10.0
	gopkg.in/jcmturner/goidentity.v3 v3.0.0
)
