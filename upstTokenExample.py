import oci

config = {
    "key_file": "private_key.pem",
    "tenancy": "ocid1.tenancy.oc1..aaaaaaaaa3qmjxr43tjexx75r6gwk6vj*****", #Update Tenancy OCID
    "region": "us-sanjose-1",
    "security_token_file": "upstToken",
    "compartment": "ocid1.compartment.oc1..aaaaaaaa5qt3a5pa7qksune7mb****", #Update Compartment OCID
}

try:
    with open(config["security_token_file"], 'r') as f:
        token = f.read()
except Exception as e:
    print(f"Error reading security token file: {e}")
    exit(1)

try:
    private_key = oci.signer.load_private_key_from_file(config['key_file'])
except Exception as e:
    print(f"Error loading private key: {e}")
    exit(1)

signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
object_storage_client = oci.object_storage.ObjectStorageClient(config,signer=signer)

# Get the namespace
try:
    namespace = object_storage_client.get_namespace().data
    print("Object Storage Namespace:", namespace)
except oci.exceptions.ServiceError as e:
    print("Error fetching namespace:", e)
    
identity_client = oci.identity.IdentityClient(config, signer=signer)
identity_client.base_client.set_region(config['region'])
# Get the list of compartments
try:
    compartments = identity_client.list_compartments(
        compartment_id=config['tenancy'],
        compartment_id_in_subtree=True
    ).data
    print("Compartments:")
    for compartment in compartments:
        print(f" - {compartment.name} (OCID: {compartment.id})")
except oci.exceptions.ServiceError as e:
    print("Error fetching compartments:", e)

networking_client = oci.core.VirtualNetworkClient(config, signer=signer)
networking_client.base_client.set_region(config['region'])
# Get the list of VCNs
try:
    vcn_list = networking_client.list_vcns(
        compartment_id=config['compartment']
    ).data
    print("VCNs:")
    for vcn in vcn_list:
        print(f" - {vcn.display_name} (OCID: {vcn.id})")
except oci.exceptions.ServiceError as e:
    print("Error fetching VCNs:", e)
