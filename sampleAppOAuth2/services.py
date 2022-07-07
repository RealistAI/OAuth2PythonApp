import requests

import base64
import json
import random

from google.cloud import secretmanager
import google_crc32c

from jose import jwk
from datetime import datetime

from django.conf import settings

from sampleAppOAuth2 import getDiscoveryDocument
from sampleAppOAuth2.models import Bearer


# token can either be an accessToken or a refreshToken
def revokeToken(token):
    revoke_endpoint = getDiscoveryDocument.revoke_endpoint
    auth_header = 'Basic ' + stringToBase64(settings.CLIENT_ID + ':' + settings.CLIENT_SECRET)
    headers = {'Accept': 'application/json', 'content-type': 'application/json', 'Authorization': auth_header}
    payload = {'token': token}
    r = requests.post(revoke_endpoint, json=payload, headers=headers)

    if r.status_code >= 500:
        return 'internal_server_error'
    elif r.status_code >= 400:
        return 'Token is incorrect.'
    else:
        return 'Revoke successful'


def getBearerToken(auth_code):
    token_endpoint = getDiscoveryDocument.token_endpoint
    auth_header = 'Basic ' + stringToBase64(settings.CLIENT_ID + ':' + settings.CLIENT_SECRET)
    headers = {'Accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded',
               'Authorization': auth_header}
    payload = {
        'code': auth_code,
        'redirect_uri': settings.REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    r = requests.post(token_endpoint, data=payload, headers=headers)
    if r.status_code != 200:
        return r.text
    bearer_raw = json.loads(r.text)

    if 'id_token' in bearer_raw:
        idToken = bearer_raw['id_token']
    else:
        idToken = None

    return Bearer(bearer_raw['x_refresh_token_expires_in'], bearer_raw['access_token'], bearer_raw['token_type'],
                  bearer_raw['refresh_token'], bearer_raw['expires_in'], idToken=idToken)


def getBearerTokenFromRefreshToken(refresh_Token):
    token_endpoint = getDiscoveryDocument.token_endpoint
    auth_header = 'Basic ' + stringToBase64(settings.CLIENT_ID + ':' + settings.CLIENT_SECRET)
    headers = {'Accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded',
               'Authorization': auth_header}
    payload = {
        'refresh_token': refresh_Token,
        'grant_type': 'refresh_token'
    }
    r = requests.post(token_endpoint, data=payload, headers=headers)
    bearer_raw = json.loads(r.text)

    if 'id_token' in bearer_raw:
        idToken = bearer_raw['id_token']
    else:
        idToken = None

    return Bearer(bearer_raw['x_refresh_token_expires_in'], bearer_raw['access_token'], bearer_raw['token_type'],
                  bearer_raw['refresh_token'], bearer_raw['expires_in'], idToken=idToken)


def get_invoices(access_token, realmId):
    auth_header = 'Bearer ' + access_token
    headers = {'Accept': 'application/json', 'Authorization': auth_header, 'accept': 'application/json'}
    sql_statement = 'select * from Invoice'
    route = '/v3/company/{realmId}/query?query={sql_statement}&minorversion=65'
    r = requests.get(settings.SANDBOX_QBO_BASEURL + route, headers=headers)
    status_code = r.status_code
    if status_code != 200:
        response = ''
        return response, status_code
    response = json.loads(r.text)
    return response,status_code
    

def getUserProfile(access_token):
    auth_header = 'Bearer ' + access_token
    headers = {'Accept': 'application/json', 'Authorization': auth_header, 'accept': 'application/json'}
    r = requests.get(settings.SANDBOX_PROFILE_URL, headers=headers)
    status_code = r.status_code
    response = json.loads(r.text)
    return response, status_code


def getCompanyInfo(access_token, realmId):
    route = '/v3/company/{0}/companyinfo/{0}'.format(realmId)
    auth_header = 'Bearer ' + access_token
    headers = {'Authorization': auth_header, 'accept': 'application/json'}
    r = requests.get(settings.SANDBOX_QBO_BASEURL + route, headers=headers)
    status_code = r.status_code
    if status_code != 200:
        response = ''
        return response, status_code
    response = json.loads(r.text)
    return response, status_code


# The validation steps can be found at ours docs at developer.intuit.com
def validateJWTToken(token):
    current_time = (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()
    token_parts = token.split('.')
    idTokenHeader = json.loads(base64.b64decode(token_parts[0]).decode('ascii'))
    idTokenPayload = json.loads(base64.b64decode(incorrect_padding(token_parts[1])).decode('ascii'))

    if idTokenPayload['iss'] != settings.ID_TOKEN_ISSUER:
        return False
    elif idTokenPayload['aud'][0] != settings.CLIENT_ID:
        return False
    elif idTokenPayload['exp'] < current_time:
        return False

    token = token.encode()
    token_to_verify = token.decode("ascii").split('.')
    message = token_to_verify[0] + '.' + token_to_verify[1]
    idTokenSignature = base64.urlsafe_b64decode(incorrect_padding(token_to_verify[2]))

    keys = getKeyFromJWKUrl(idTokenHeader['kid'])

    publicKey = jwk.construct(keys)
    return publicKey.verify(message.encode('utf-8'), idTokenSignature)


def getKeyFromJWKUrl(kid):
    jwk_uri = getDiscoveryDocument.jwks_uri
    r = requests.get(jwk_uri)
    if r.status_code >= 400:
        return ''
    data = json.loads(r.text)

    key = next(ele for ele in data["keys"] if ele['kid'] == kid)
    return key


# for decoding ID Token
def incorrect_padding(s):
    return s + '=' * (4 - len(s) % 4)


def stringToBase64(s):
    return base64.b64encode(bytes(s, 'utf-8')).decode()


# Returns a securely generated random string. Source from the django.utils.crypto module.
def getRandomString(length, allowed_chars='abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    return ''.join(random.choice(allowed_chars) for i in range(length))


# Create a random secret key. Source from the django.utils.crypto module.
def getSecretKey():
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return getRandomString(40, chars)

def create_secret(project_id, secret_id):
    """
    Create a new secret with the given name. A secret is a logical wrapper
    around a collection of secret versions. Secret versions hold the actual
    secret material.
    """

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the parent project.
    parent = f"projects/{project_id}"

    # Create the secret.
    response = client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
    )

    # Print the new secret name.
    print("Created secret: {}".format(response.name))

def add_secret_version(project_id, secret_id, payload):
    """
    Add a new secret version to the given secret with the provided payload.
    """

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the parent secret.
    parent = client.secret_path(project_id, secret_id)

    # Convert the string payload into a bytes. This step can be omitted if you
    # pass in bytes instead of a str for the payload argument.
    payload = payload.encode("UTF-8")

    # Calculate payload checksum. Passing a checksum in add-version request
    # is optional.
    crc32c = google_crc32c.Checksum()
    crc32c.update(payload)

    # Add the secret version.
    response = client.add_secret_version(
        request={
            "parent": parent,
            "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
        }
    )

    # Print the new secret version name.
    print("Added secret version: {}".format(response.name))

def access_secret_version(secret_id):
    """
    Access the payload for the given secret version if one exists. The version
    can be a version number as a string (e.g. "5") or an alias (e.g. "latest").
    """
    project_id = 'michael-gilbert-dev'
    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version.
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"

    # Access the secret version.
    response = client.access_secret_version(request={"name": name})

    # Verify payload checksum.
    crc32c = google_crc32c.Checksum()
    crc32c.update(response.payload.data)
    if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        print("Data corruption detected.")
        return response

    # Print the secret payload.
    #
    # WARNING: Do not print the secret in a production environment - this
    # snippet is showing how to access the secret material.
    payload = response.payload.data.decode("UTF-8")
    print("Plaintext: {}".format(payload))

def cache_tokens(project_id, access_token, refresh_token, company_name):
    company_token = f"{company_name}_token"
    payload = f"{access_token} {refresh_token}"
    try:
        create_secret(project_id=project_id, secret_id=company_token)
        add_secret_version(project_id=project_id, secret_id=company_token, payload=payload)
    except:
        add_secret_version(project_id=project_id, secret_id=company_token, payload=payload)
