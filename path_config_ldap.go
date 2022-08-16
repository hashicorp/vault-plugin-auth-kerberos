package kerberos

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const ldapConfPath = "config/ldap"

func (b *backend) pathConfigLdap() *framework.Path {
	p := &framework.Path{
		Pattern: ldapConfPath,
		Fields:  ldaputil.ConfigFields(),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigLdapRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigLdapWrite,
			},
		},
		HelpSynopsis:    pathConfigLdapHelpSyn,
		HelpDescription: pathConfigLdapHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)
	p.Fields["token_policies"].Description += ". This will apply to all tokens generated by this auth method, in addition to any configured for specific users/groups."
	return p
}

// ConfigLDAP reads the present ldap config.
func (b *backend) ConfigLdap(ctx context.Context, req *logical.Request) (*ldapConfigEntry, error) {
	entry, err := req.Storage.Get(ctx, ldapConfPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	cfg := &ldapConfigEntry{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (b *backend) pathConfigLdapRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	data := cfg.PasswordlessMap()
	cfg.PopulateTokenData(data)

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathConfigLdapWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, err
	}

	var prevLDAPCfg *ldaputil.ConfigEntry
	if cfg != nil && cfg.ConfigEntry != nil {
		// Use the previous ConfigEntry.
		prevLDAPCfg = cfg.ConfigEntry
	} else if cfg == nil {
		// Prevent nil pointer exceptions.
		cfg = &ldapConfigEntry{}
	}

	newLdapCfg, err := ldaputil.NewConfigEntry(prevLDAPCfg, d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	cfg.ConfigEntry = newLdapCfg

	// Read in the token fields that have been sent and set
	// them on the cfg struct.
	if err := cfg.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON(ldapConfPath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

type ldapConfigEntry struct {
	tokenutil.TokenParams
	*ldaputil.ConfigEntry
}

const pathConfigLdapHelpSyn = `
Configure the LDAP server to connect to, along with its options.
`

const pathConfigLdapHelpDesc = `
This endpoint allows you to configure the LDAP server to connect to and its
configuration options.

The LDAP URL can use either the "ldap://" or "ldaps://" schema. In the former
case, an unencrypted connection will be made with a default port of 389, unless
the "starttls" parameter is set to true, in which case TLS will be used. In the
latter case, a SSL connection will be established with a default port of 636.

## A NOTE ON ESCAPING

It is up to the administrator to provide properly escaped DNs. This includes
the user DN, bind DN for search, and so on.

The only DN escaping performed by this backend is on usernames given at login
time when they are inserted into the final bind DN, and uses escaping rules
defined in RFC 4514.

Additionally, Active Directory has escaping rules that differ slightly from the
RFC; in particular it requires escaping of '#' regardless of position in the DN
(the RFC only requires it to be escaped when it is the first character), and
'=', which the RFC indicates can be escaped with a backslash, but does not
contain in its set of required escapes. If you are using Active Directory and
these appear in your usernames, please ensure that they are escaped, in
addition to being properly escaped in your configured DNs.

For reference, see https://www.ietf.org/rfc/rfc4514.txt and
http://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
`
