import oci
import configparser
import requests
import json
import base64

# This is Python code to do Identity Propagation trust configuration with OCI IAM. The user that is running the script has to be an Application Administrator in the OCI IAM domain. 

# Import required libraries
# oci: Oracle Cloud Infrastructure SDK
# configparser: For reading configuration files
# requests: For making HTTP requests
# json: For handling JSON data
# base64: For encoding credentials

# The rest of the code loads configuration, defines an OAuthClient class, and provides functions to:
# - Create and activate OAuth clients
# - Grant admin roles to clients
# - Generate OAuth tokens
# - Create service users
# - Set up identity propagation trust

# The steps to create Identity Propagation trust are:
# 1. Create Identity Domain Administrator OAuth client and Activate the client
# 2. Create Token Exchange OAuth client and activate the client
# 3. Create service user to be used for Impersonation
# 4. Create Identity Propagation Trust
    
# Define a class to represent an OAuth client with its relevant attributes
class OAuthClient:
    def __init__(self, id, ocid, clientid, clientsecret):
        # Unique identifier of the client within the domain
        self.id = id
        # Oracle Cloud Identifier (OCID) for the client
        self.ocid = ocid
        # Client ID used for OAuth authentication
        self.clientid = clientid
        # Client secret used for OAuth authentication
        self.clientsecret = clientsecret
        
def activateOAuthClient(identity_domains_client, clientApp):
    """
    Activates the specified OAuth client application in OCI Identity Domains.

    Args:
        identity_domains_client: The OCI IdentityDomainsClient instance.
        clientApp: An instance of OAuthClient representing the app to activate.
    """
    put_app_status_changer_response = identity_domains_client.put_app_status_changer(
        app_status_changer_id=clientApp.ocid,
        app_status_changer=oci.identity_domains.models.AppStatusChanger(
            schemas=["urn:ietf:params:scim:schemas:oracle:idcs:AppStatusChanger"],
            active=True,
            id=clientApp.ocid #OCID of the OAuth client app to be activated
        )
    )

def createOAuthClient(identity_domains_client, app_name):
    try:
        # Define confidential application details
        create_app_response = identity_domains_client.create_app(
            app=oci.identity_domains.models.App(
                schemas=[
                    "urn:ietf:params:scim:schemas:oracle:idcs:App"
                ],
                display_name=app_name,
                based_on_template=oci.identity_domains.models.AppBasedOnTemplate(
                    value="CustomWebAppTemplateId")
            )
        )
        if create_app_response.status == 401:
            print("OAuth client app creation failed. Make sure the Principal being used has Application Administrator privilege in the OCI IAM domain.")
            exit()
        elif create_app_response.status != 201:
            print(f"OAuth client app creation failed with status code: {create_app_response.status}")
            exit()
    except Exception as e:
        print(f"Exception during OAuth client app creation: {e}")
        exit()

    print(f"Confidential application creation completed with status code: {create_app_response.status} and the resource OCID is: {create_app_response.data.ocid}")
    applicationID = create_app_response.data.id

    try:
        patch_app_response = identity_domains_client.patch_app(
            app_id=applicationID,
            patch_op=oci.identity_domains.models.PatchOp(
                schemas=["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                operations=[
                    oci.identity_domains.models.Operations(
                        op="REMOVE",
                        path="allowOffline"
                    ),
                    oci.identity_domains.models.Operations(
                        op="REMOVE",
                        path="bypassConsent"
                    ),
                    oci.identity_domains.models.Operations(
                        op="ADD",
                        path="allowedGrants",
                        value=["client_credentials"]
                    ),
                    oci.identity_domains.models.Operations(
                        op="ADD",
                        path="clientType",
                        value="confidential"
                    ),
                    oci.identity_domains.models.Operations(
                        op="REPLACE",
                        path="isOAuthClient",
                        value=True
                    )
                ]
            )
        )
    except Exception as e:
        print(f"Exception during patching OAuth client app: {e}")
        exit()

    if not hasattr(patch_app_response.data, "name") or not hasattr(patch_app_response.data, "client_secret"):
        print("Failed to retrieve client ID or client secret from patch response.")
        exit()

    print(f"ClientID of the app is {patch_app_response.data.name} and Client Secret is {patch_app_response.data.client_secret}")
    clientApp = OAuthClient(create_app_response.data.id, create_app_response.data.ocid, patch_app_response.data.name, patch_app_response.data.client_secret)
    try:
        activateOAuthClient(identity_domains_client, clientApp)
    except Exception as e:
        print(f"Exception during OAuth client activation: {e}")
        exit()
    return clientApp

def grantAdminRole(identity_domains_client,clientApp):
    try:
        list_app_roles_response = identity_domains_client.list_app_roles(
            filter='displayName eq "Identity Domain Administrator"'
        )
        if( not list_app_roles_response.data or not list_app_roles_response.data.resources):
            print("No app roles found.")
            exit()
        print("ID of the Identity Domain Administrator role is: ",list_app_roles_response.data.resources[0].id)
    except Exception as e:
        print(f"Exception during listing app roles: {e}")
        exit()

    try:
        create_grant_response = identity_domains_client.create_grant(
            grant=oci.identity_domains.models.Grant(
                schemas=["urn:ietf:params:scim:schemas:oracle:idcs:Grant"],
                grant_mechanism="ADMINISTRATOR_TO_APP",
                grantee=oci.identity_domains.models.GrantGrantee(
                    value=clientApp.id,
                    type="App"
                ),
                app=oci.identity_domains.models.GrantApp(
                    value="IDCSAppId"
                ),
                entitlement=oci.identity_domains.models.GrantEntitlement(
                    attribute_name="appRoles",
                    attribute_value=list_app_roles_response.data.resources[0].id
                )
            )
        )
    except Exception as e:
        print(f"Exception during grant creation: {e}")
        exit()
    if(not create_grant_response.data.id):
        print("Grant creation or Domain Administrator role assignment failed.")
        exit()
    print("Grant created: ",create_grant_response.data.id)

def generate_basic_auth_header(clientid,clientsecret):
    credentials = f"{clientid}:{clientsecret}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded_credentials}"
    
def generateAdminOauthToken(adminOauthClient, iamDomain):
    url = f"{iamDomain}/oauth2/v1/token"
    payload = 'grant_type=client_credentials&scope=urn%3Aopc%3Aidm%3A__myscopes__&Sec-Fetch-Site=same-site&Sec-Fetch-Dest=empty&Sec-Fetch-Mode=cors'
    authHeader = generate_basic_auth_header(adminOauthClient.clientid, adminOauthClient.clientsecret)
    print(f"OAuth token AuthHeader is: {authHeader}")
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': authHeader
    }
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        response.raise_for_status()
        jsonResponse = json.loads(response.text)
        if "access_token" not in jsonResponse:
            print("Error: access_token not found in response.")
            print(f"Response: {response.text}")
            exit()
        return jsonResponse["access_token"]
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
        print(f"Response: {getattr(e.response, 'text', '')}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {e}")
        print(f"Response: {response.text}")
        exit()
    
def createServiceUser(username, AdminOauthToken, iamDomain):
    url = f"{iamDomain}/admin/v1/Users"
    authHeader = f"Bearer {AdminOauthToken}"
    payload = json.dumps({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User"
        ],
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User": {
            "serviceUser": True
        },
        "userName": username
    })
    headers = {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        response.raise_for_status()
        jsonResponse = json.loads(response.text)
        if "ocid" not in jsonResponse:
            print("Error: OCID not found in service user creation response.")
            print(f"Response: {response.text}")
            exit()
        print(f"Service user OCID: {jsonResponse['ocid']}")
        return jsonResponse["ocid"]
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
        print(f"Response: {getattr(e.response, 'text', '')}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {e}")
        print(f"Response: {response.text}")
        exit()

def createIdentityPropagationTrust(AdminOauthToken, TrustedClientID, serviceUserOCID, issuer, jwkEndpoint, ImpersonationRule, iamDomain):
    url = f"{iamDomain}/admin/v1/IdentityPropagationTrusts"
    authHeader = f"Bearer {AdminOauthToken}"
    payload = json.dumps({
        "active": True,
        "allowImpersonation": True,
        "issuer": issuer,
        "publicKeyEndpoint": jwkEndpoint,
        "name": "Token Trust for IDP",
        "oauthClients": [
            TrustedClientID
        ],
        "impersonationServiceUsers": [
            {
                "ocid": serviceUserOCID,
                "rule": ImpersonationRule
            }
        ],
        "subjectType": "User",
        "type": "JWT",
        "schemas": [
            "urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"
        ]
    })
    headers = {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        response.raise_for_status()
        print(f"Trust creation response is: {response.text}")
        jsonResponse = json.loads(response.text)
        if "id" not in jsonResponse:
            print("Error: Trust creation did not return an ID.")
            print(f"Response: {response.text}")
            exit()
        print(f"Identity Propagation Trust created with ID: {jsonResponse['id']}")
        return jsonResponse["id"]
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
        print(f"Response: {getattr(e.response, 'text', '')}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {e}")
        print(f"Response: {response.text}")
        exit()
    
def wifConfiguration():        
    
    config=configparser.ConfigParser()
    try:
        config.read('setupConfig.ini')
    except configparser.Error as e:
        print(f"Error reading config file: {e}")
        exit()
        
    try:
        IAM_GUID = config['IdentityDomain']['IAM_GUID']
        CLI_PROFILE = config['OCIConfig']['CLI_PROFILE']
        ADMIN_APP_NAME=config['WIFConfig']['ADMIN_APP_NAME']
        TOKEN_EXCHANGE_APP_NAME=config['WIFConfig']['TOKEN_EXCHANGE_APP_NAME']
        SERVICE_USER=config['ServiceUserConfig']['USER_NAME']
        ISSUER=config['TrustConfiguration']['ISSUER']
        JWK_URI=config['TrustConfiguration']['JWK_URI']
        IMPERSONATIONRULE=config['TrustConfiguration']['IMPERSONATIONRULE']
        print(f"IAM Domain GUID is: {IAM_GUID}")
        print(f"OCI CLI Profile to be used is: {CLI_PROFILE}")
    except KeyError as e:
        print(f"Missing key in config file: {e}")
    except ValueError as e:
        print(f"Invalid value type in config file: {e}")
        
    # Set up OCI config (ensure your ~/.oci/config is set up)
    config = oci.config.from_file(profile_name=CLI_PROFILE)

    # Initialize Identity Domains client
    identity_domains_client = oci.identity_domains.IdentityDomainsClient(config,IAM_GUID)
        
    #Lets first create an Admin OAuth client
    AdminOAuthClient = createOAuthClient(identity_domains_client,ADMIN_APP_NAME)
    grantAdminRole(identity_domains_client,AdminOAuthClient)
    AdminOauthToken = generateAdminOauthToken(AdminOAuthClient,IAM_GUID)

    TokenExchangeOAuthClient = createOAuthClient(identity_domains_client,TOKEN_EXCHANGE_APP_NAME)
    
    #Update runtimeConfig.ini with OAuth client details
    try:
        runtimeConfig = configparser.ConfigParser()
        runtimeConfig.read('runtimeConfig.ini')
        runtimeConfig['WIFConfig']['OAuthClientID'] = TokenExchangeOAuthClient.clientid
        runtimeConfig['WIFConfig']['OAuthClientSecret'] = TokenExchangeOAuthClient.clientsecret
        with open('runtimeConfig.ini', 'w') as configfile:
            runtimeConfig.write(configfile) 
    except configparser.Error as e:
        print(f"Error writing to runtimeConfig.ini: {e}")
        
    serviceUserOCID = createServiceUser(SERVICE_USER,AdminOauthToken,IAM_GUID)
    createIdentityPropagationTrust(AdminOauthToken,TokenExchangeOAuthClient.clientid,serviceUserOCID,ISSUER,JWK_URI,IMPERSONATIONRULE,IAM_GUID)

#Invoke Workload Identity Federation Configuration function.
wifConfiguration()