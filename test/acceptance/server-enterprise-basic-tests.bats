#!/usr/bin/env bats

load _helpers

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_LICENSE=${VAULT_LICENSE?}
export VAULT_NAMESPACE=${VAULT_NAMESPACE:-"admin/"}

VAULT_PLUGIN_SHA=$(openssl dgst -sha256 pkg/linux_amd64/vault-plugin-auth-kerberos|cut -d ' ' -f2)

# setup sets up the infrastructure required for running these tests
setup() {
  start_infrastructure
  sleep 15

  setup_users
  add_vault_spn
  prepare_outer_environment
}

teardown() {
  stop_infrastructure
}

create_namespace() {
  new_namespace=${VAULT_NAMESPACE}
  VAULT_NAMESPACE=""
  vault namespace create "$new_namespace"
}

register_plugin() {
  plugin_binary_path="$(plugin_dir)/vault-plugin-auth-kerberos"
  VAULT_PLUGIN_SHA=$(openssl dgst -sha256 "$plugin_binary_path" | cut -d ' ' -f2)
  VAULT_NAMESPACE=""

  vault write sys/plugins/catalog/auth/kerberos sha_256="${VAULT_PLUGIN_SHA}" command="vault-plugin-auth-kerberos"
}

enable_and_config_auth_kerberos() {
  vault auth enable \
    -path=kerberos \
    -passthrough-request-headers=Authorization \
    -allowed-response-headers=www-authenticate \
    vault-plugin-auth-kerberos

  vault write auth/kerberos/config \
    keytab=@vault_svc.keytab.base64 \
    service_account="vault_svc"

  vault write auth/kerberos/config/ldap \
    binddn="${DOMAIN_VAULT_ACCOUNT}"@"${REALM_NAME}" \
    bindpass="${DOMAIN_VAULT_PASS}" \
    groupattr=sAMAccountName \
    groupdn="${DOMAIN_DN}" \
    groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \
    insecure_tls=true \
    starttls=true \
    userdn="CN=Users,${DOMAIN_DN}" \
    userattr=sAMAccountName \
    upndomain="${REALM_NAME}" \
    url=ldaps://"${SAMBA_CONTAINER:0:12}"."${DNS_NAME}"
}

login_kerberos() {
  docker cp "${BATS_TEST_DIRNAME}"/auth-check.py "$DOMAIN_JOINED_CONTAINER":/home
  docker exec -it "$DOMAIN_JOINED_CONTAINER" python /home/auth-check.py "$VAULT_CONTAINER" "${VAULT_NAMESPACE}"
}

@test "auth/kerberos: setup and authentication within a Vault namespace" {
  create_namespace
  register_plugin
  enable_and_config_auth_kerberos

  run login_kerberos
  [ "${status?}" -eq 0 ]

  [[ "${output?}" =~ ^Vault[[:space:]]token\:[[:space:]].+$ ]]
}

