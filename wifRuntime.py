import requests
import configparser
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import urllib.parse

def generate_basic_auth_header(clientid,clientsecret):
    credentials = f"{clientid}:{clientsecret}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded_credentials}"

def tokenExchange(IAM_DOMAIN, OAuthClientID, OAuthClientSecret, SubjectToken):
    """
    Exchanges a subject token for an OCI upst token using OAuth 2.0 Token Exchange.
    This function generates a new RSA key pair, encodes the public key, and sends a token exchange request
    to the specified IAM domain. The private key is saved to 'private_key.pem' in PEM format. The function
    returns the exchanged token if successful.
    Args:
        IAM_DOMAIN (str): The base URL of the IAM domain (e.g., "https://idcs.example.com").
        OAuthClientID (str): The OAuth 2.0 client ID for authentication.
        OAuthClientSecret (str): The OAuth 2.0 client secret for authentication.
        SubjectToken (str): The JWT subject token to be exchanged.
    Returns:
        str or None: The exchanged OCI upst token if successful, otherwise None.
    Notes:
        - The function generates a new RSA key pair on each call and overwrites 'private_key.pem'.
        - The public key is base64-encoded and URL-encoded before being sent in the request.
        - The function expects the response JSON to contain a 'token' field.
        - The function prints debug information, including the public key, payload, and headers.
        - If the response status code is not 200 or the 'token' field is missing, None is returned.
        - The function depends on external functions and modules such as `generate_basic_auth_header`, `rsa`, `serialization`, `default_backend`, `base64`, `urllib`, `requests`, and `json`.
    """
    url = f"{IAM_DOMAIN}/oauth2/v1/token"
    
    # Generate RSA key pair and public key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    
    public_key_b64 = urllib.parse.quote(public_key_b64, safe='')
    print(f"Public Key: {public_key_b64}")
    
    # Write private key to a file
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    payload = f'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&requested_token_type=urn:oci:token-type:oci-upst&subject_token={SubjectToken}&subject_token_type=jwt&public_key={public_key_b64}'
    authHeader = generate_basic_auth_header(OAuthClientID, OAuthClientSecret)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': authHeader
    }
    print(f"Payload is: {payload}")
    print(f"Headers are: {headers}")
    # Make the POST request to exchange the token
    response = requests.post(url, headers=headers, data=payload)
    if response.status_code != 200:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    #print(f"Response is: {response.text}")
    jsonResponse = json.loads(response.text)
    if 'token' not in jsonResponse:
        print("Error: 'access_token' not found in response")
        return None
    #print(f"Token exchange successful: {jsonResponse['token']}")
    return jsonResponse['token']

config=configparser.ConfigParser()
try:
    config.read('runtimeConfig.ini')
except configparser.Error as e:
    print(f"Error reading config file: {e}")
    exit()
        
try:
    OAuthClientID = config.get('WIFConfig', 'oauthclientid')
    OAuthClientSecret = config.get('WIFConfig', 'oauthclientsecret')
    SubjectToken = config.get('WIFConfig', 'subjecttoken')
    IAM_GUID = config.get('IdentityDomain', 'iam_guid')
    print(f"IAM Domain GUID is: {IAM_GUID}")
except KeyError as e:
    print(f"Missing key in config file: {e}")
except ValueError as e:
    print(f"Invalid value type in config file: {e}")
upstToken = tokenExchange(IAM_GUID, OAuthClientID, OAuthClientSecret, SubjectToken)
with open('upstToken', 'w') as f:
    f.write(upstToken)
print("UPST Token written to upstToken")
print(f"UPST Token: {upstToken}")