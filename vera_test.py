#!/usr/bin/python
import hashlib, base64, json, httplib, getpass, urlparse, urllib

def doHttpsRequest(host, url, verb='GET', headers={}):
    conn = httplib.HTTPSConnection(host)

    conn.request(verb, url, headers=headers)

    response = conn.getresponse()

    return response.read()


def getSHAUserPassword(username, password):
    return hashlib.sha1(username + password + 'oZ7QE6LcLJp6fiWzdqZc').hexdigest()


AuthToken = None
AuthSigToken = None

def getSessionTokenHeaders(host):
    global AuthToken
    global AuthSigToken

    sessionTokenRequestHeaders = {
        'MMSAuth': AuthToken,
        'MMSAuthSig': AuthSigToken
    }

    response = doHttpsRequest(host, '/info/session/token', headers=sessionTokenRequestHeaders)

    return { 'MMSSession': response }


session_tokens = {}

def doSessionRequest(host, url):
    global session_tokens

    sessionRequestHeaders = session_tokens.get(host, None)

    if sessionRequestHeaders is None:
        sessionRequestHeaders = getSessionTokenHeaders(host)
        session_tokens[host] = sessionRequestHeaders

    return doHttpsRequest(host, url, headers=sessionRequestHeaders)


def main():
    global AuthToken
    global AuthSigToken

    UserID = raw_input('Username: ')
    UserPassword = getpass.getpass('Password: ')

    LowerUserID = UserID.lower()

    SHA1UserPassword = getSHAUserPassword(LowerUserID, UserPassword)

    response = doHttpsRequest('us-autha11.mios.com', '/autha/auth/username/' + LowerUserID + '?SHA1Password=' + SHA1UserPassword + '&PK_Oem=1')

    obj = json.loads(response)

    AuthToken = obj['Identity']
    AuthSigToken = obj['IdentitySignature']
    Server_Account = obj['Server_Account']

    PK_Account = json.loads(base64.b64decode(AuthToken))['PK_Account']

    response = doSessionRequest(Server_Account, '/account/account/account/' + str(PK_Account) + '/devices')

    obj = json.loads(response)

    Devices = obj['Devices']

    selected_index = -1

    while selected_index < 0 or selected_index >= len(Devices):
        print ''
        print 'Found Devices:'
        for idx, device in enumerate(Devices):
            print str(idx), urllib.unquote_plus(device['Platform']), urllib.unquote_plus(device['Name']), urllib.unquote_plus(device['PK_Device'])

        print ''
        try:
            selected_index = int(raw_input('Choose a device: '))
        except:
            pass

    ServerDevice = Devices[selected_index]['Server_Device']
    PK_Device = Devices[selected_index]['PK_Device']

    response = doSessionRequest(ServerDevice, '/device/device/device/' + PK_Device)

    obj = json.loads(response)

    ServerRelay = obj['Server_Relay']
    InternalIP = obj['InternalIP']

    print ''
    print 'See http://wiki.micasaverde.com/index.php/Luup_Requests for example requests.'

    while True:
        print ''
        request = raw_input('Request ( ex: /data_request?id=sdata ) (Press Ctrl-C to quit): ')
        response = doSessionRequest(ServerRelay, '/relay/relay/relay/device/' + PK_Device + '/port_3480' + request)

        print response

if __name__ == "__main__":
    main()
