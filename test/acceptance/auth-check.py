import kerberos
import requests
import sys

prefix = sys.argv[1]

host = prefix + ".matrix.lan:8200"
service = "HTTP@{}".format(host)
rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
kerberos.authGSSClientStep(vc, "")
kerberos_token = kerberos.authGSSClientResponse(vc)

r = requests.post("http://{}/v1/admin/auth/kerberos/login".format(host),
                  headers={'Authorization': 'Negotiate ' + kerberos_token})
print('Vault token:', r.json()['auth']['client_token'])