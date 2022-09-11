import base64
import getpass
import requests

def call_security_method(security_method, user_name, user_password):
    """ Create API call security method
        @param security_method string: Security method to use: basic or kerberos
        @param user_name string: The user's credentials name
        @param user_password string: The user's credentials password
    """
    from requests.auth import HTTPBasicAuth
    from requests_kerberos import HTTPKerberosAuth

    if security_method.lower() == 'basic':
        security_auth = HTTPBasicAuth(user_name, user_password)
    else:
        security_auth = HTTPKerberosAuth(mutual_authentication='REQUIRED',
                                         sanitize_mutual_error_response=False)

    return security_auth

# Get user credentials
UN = 'PI\Administrator'
PW = "!PISystem123!"

# Server info
FQDN = "172.23.234.49"
WEBID = "F1AbErnuSOoCCMUmsfkJxwSrgwAQ76m7qby7BGDfAAMKXFIbAQyu9SEBSlkeW0c0ZP56f4gUElTRVJWRVJcUFJPRFVDVElPTlxQTEFOVCBBXEFSRUEgMVxNT1RPUiAxfFRBRzI"

# Convert user credentials to auth header
auth_string = '%s:%s' % (UN, PW)
auth_base64 = base64.b64encode(str.encode(auth_string))
auth = 'Basic %s' % (auth_base64.decode())

# Generate request headers
headers = {
    'Authorization': auth
}

req_url = f'https://{FQDN}/piwebapi/streams/{WEBID}/recorded'
security_method = call_security_method('Kerberos', UN, PW)

# Make request
r = requests.get(req_url, auth=security_method, verify=False) # Set verify=False to allow bad dev SSL cert.

# If request was successful, convert response to json object.
if r.status_code == 200:
    response_body = r.json
