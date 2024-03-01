module github.com/hashicorp/vault-plugin-auth-kerberos

go 1.12

require (
	github.com/docker/docker v24.0.9+incompatible // indirect
	github.com/go-ldap/ldap/v3 v3.4.6
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.6.2
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/vault/api v1.12.0
	github.com/hashicorp/vault/sdk v0.11.0
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/ory/dockertest/v3 v3.10.0
	google.golang.org/grpc v1.61.0 // indirect
	gopkg.in/jcmturner/goidentity.v3 v3.0.0
)
