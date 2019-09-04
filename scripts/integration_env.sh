#!/bin/bash

VAULT_VER=1.2.2
VAULT_PORT=18200
SAMBA_VER=4.8.12

export VAULT_TOKEN=${VAULT_TOKEN:-myroot}
DOMAIN_ADMIN_PASS=Pa55word!
DOMAIN_VAULT_ACCOUNT=vault_svc
DOMAIN_VAULT_PASS=vaultPa55word!
DOMAIN_USER_ACCOUNT=grace
DOMAIN_USER_PASS=gracePa55word!

SAMBA_CONF_FILE=/srv/etc/smb.conf
DOMAIN_NAME=matrix
DNS_NAME=matrix.lan
REALM_NAME=MATRIX.LAN
DOMAIN_DN=DC=MATRIX,DC=LAN
TESTS_DIR=/tmp/vault_plugin_tests

function start_infrastructure() {
  create_network
  start_domain
  start_vault
}

function stop_infrastructure() {
  stop_vault
  stop_domain
  delete_network
}

function create_network() {
  docker network create ${DNS_NAME}
}

function delete_network() {
  docker network rm ${DNS_NAME}
}

function start_vault() {
  VAULT_CONTAINER=$(docker run --net=${DNS_NAME} -d -ti --cap-add=IPC_LOCK -v $(pwd)/pkg/linux_amd64:/plugins:Z -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:${VAULT_PORT}" -p ${VAULT_PORT}:${VAULT_PORT} vault:${VAULT_VER} server -dev -dev-plugin-dir=/plugins) # shouldn't need to publish all these ports as they are only used within the docker network, but figured it may be useful for debugging
  export VAULT_ADDR=http://127.0.0.1:${VAULT_PORT}
}

function stop_vault() {
  docker rm -f ${VAULT_CONTAINER}
}

function start_domain() {
  SAMBA_CONTAINER=$(docker run --net=${DNS_NAME} -d -ti --privileged -p 135:135 -p 137:137 -p 138:138 -p 139:139 -p 389:389 -p 445:445 -p 464:464 -p 636:636 -p 3268:3268 -p 3269:3269 -e "SAMBA_DC_ADMIN_PASSWD=${DOMAIN_ADMIN_PASS}" -e "KERBEROS_PASSWORD=${DOMAIN_ADMIN_PASS}" -e SAMBA_DC_DOMAIN=${DOMAIN_NAME} -e SAMBA_DC_REALM=${REALM_NAME} "bodsch/docker-samba4:${SAMBA_VER}") # shouldn't need to publish all these ports as they are only used within the docker network, but figured it may be useful for debugging
}

function stop_domain() {
  docker rm -f ${SAMBA_CONTAINER}
}

function setup_users() {
  add_user $DOMAIN_VAULT_ACCOUNT $DOMAIN_VAULT_PASS
  create_keytab $DOMAIN_VAULT_ACCOUNT $DOMAIN_VAULT_PASS

  add_user $DOMAIN_USER_ACCOUNT $DOMAIN_USER_PASS
  create_keytab $DOMAIN_USER_ACCOUNT $DOMAIN_USER_PASS
}

function add_user() {

  username="${1}"
  password="${2}"

  if [[ $(check_user ${username}) -eq 0 ]]
  then
    echo "add user '${username}'"

    docker exec $SAMBA_CONTAINER \
      /usr/bin/samba-tool user create \
      ${username} \
      ${password}\
      --configfile=${SAMBA_CONF_FILE}
  fi
}

function check_user() {

  username="${1}"

  docker exec $SAMBA_CONTAINER \
    /usr/bin/samba-tool user list \
    --configfile=${SAMBA_CONF_FILE} \
    | grep -c ${username}
}

function create_keytab() {
  
  username="${1}"
  password="${2}"

  user_kvno=$(docker exec $SAMBA_CONTAINER \
    bash -c "ldapsearch -H ldaps://localhost -D \"Administrator@${REALM_NAME}\"  -w \"${DOMAIN_ADMIN_PASS}\" -b \"CN=Users,${DOMAIN_DN}\" -LLL \"(&(objectClass=user)(sAMAccountName=${username}))\" msDS-KeyVersionNumber | sed -n 's/^[ \t]*msDS-KeyVersionNumber:[ \t]*\(.*\)/\1/p'")

  docker exec $SAMBA_CONTAINER \
    bash -c "printf \"%b\" \"addent -password -p \"${username}@${REALM_NAME}\" -k ${user_kvno} -e rc4-hmac\n${password}\nwrite_kt ${username}.keytab\" | ktutil"

  docker exec $SAMBA_CONTAINER \
    bash -c "printf \"%b\" \"read_kt ${username}.keytab\nlist\" | ktutil"

  docker exec $SAMBA_CONTAINER \
    base64 ${username}.keytab > ${username}.keytab.base64
}

function add_vault_spn() {
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12}:${VAULT_PORT} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12}.${DNS_NAME} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12}.${DNS_NAME}:${VAULT_PORT} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
}

function enable_plugin() {
  VAULT_PLUGIN_SHA=$(openssl dgst -sha256 bin/vault-plugin-auth-kerberos|cut -d ' ' -f2)
  vault write sys/plugins/catalog/auth/kerberos sha_256=${VAULT_PLUGIN_SHA} command="vault-plugin-auth-kerberos"
  vault auth enable -passthrough-request-headers=Authorization -allowed-response-headers=www-authenticate kerberos
  vault write auth/kerberos/config keytab=@vault_svc.keytab.base64 service_account="vault_svc"
  vault write auth/kerberos/config/ldap binddn=${DOMAIN_VAULT_ACCOUNT}@${REALM_NAME} bindpass=${DOMAIN_VAULT_PASS} groupattr=sAMAccountName groupdn="${DOMAIN_DN}" groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" insecure_tls=true starttls=true userdn="CN=Users,${DOMAIN_DN}" userattr=sAMAccountName upndomain=${REALM_NAME} url=ldaps://${SAMBA_CONTAINER:0:12}.${DNS_NAME}
}

function write_python_test() {
  echo "
import kerberos
import requests

host = \"${VAULT_CONTAINER:0:12}.${DNS_NAME}:${VAULT_PORT}\"
service = \"HTTP@{}\".format(host)
rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
kerberos.authGSSClientStep(vc, \"\")
kerberos_token = kerberos.authGSSClientResponse(vc)

r = requests.post(\"http://{}/v1/auth/kerberos/login\".format(host),
                  json={'authorization': 'Negotiate ' + kerberos_token})
print('Vault token:', r.json()['auth']['client_token'])
" > manual_test.py
}

function write_kerb_config() {
  echo "
[libdefaults]
  default_realm = ${REALM_NAME}
  dns_lookup_realm = false
  dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
[realms]
  ${REALM_NAME} = {
    kdc = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
    admin_server = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
    master_kdc = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
    default_domain = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
  }
" > krb5.conf
}

function prepare_files() {
  mkdir -p ${TESTS_DIR}/integration
  pushd ${TESTS_DIR}/integration
  write_kerb_config
  write_python_test
  popd
  base64 -d grace.keytab.base64 > $TESTS_DIR/integration/grace.keytab
}

function remove_files() {
  rm -fr $TESTS_DIR/integration # using superfluous child dir in case variable is blank at some point ;)
}

function start_domain_joined_container() {
  DOMAIN_JOINED_CONTAINER=$(docker run --net=${DNS_NAME} -d -v "${TESTS_DIR}/integration:/tests:Z" -e KRB5_CONFIG=/tests/krb5.conf -e KRB5_CLIENT_KTNAME=/tests/grace.keytab -t python:3.7 cat)
}

function stop_domain_joined_container() {
  docker rm -f ${DOMAIN_JOINED_CONTAINER}
}

function run_test_script() {
  docker exec $DOMAIN_JOINED_CONTAINER \
    pip install requests-kerberos
  docker exec $DOMAIN_JOINED_CONTAINER \
    python /tests/manual_test.py
  result=$?
}

function run_tests() {
  remove_files
  prepare_files
  start_domain_joined_container
  run_test_script
  stop_domain_joined_container
}

function main() {
  start_infrastructure
  sleep 15  # could loop until `ldapsearch` returns properly....
  setup_users
  add_vault_spn
  enable_plugin
  run_tests
  stop_infrastructure
  return $result
}