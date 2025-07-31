import oci

config = {
    "key_file": "private_key.pem",
    "tenancy": "ocid1.tenancy.oc1..aaaaaaaaa3qmjxr43tjexx75r6gwk6vjw22ermohbw2vbxyhczksgjir7xdq",
    "region": "us-ashburn-1",
    "security_token_file": "upstToken",
    "compartment": "ocid1.compartment.oc1..aaaaaaaa5qt3a5pa7qksune7mbd47kd3szxybaopzl55iwirl2mubzq56wga",
}

with open(config["security_token_file"], 'r') as f:
    token = f.read()
private_key = oci.signer.load_private_key_from_file(config['key_file'])

signer = oci.auth.signers.SecurityTokenSigner(token, private_key)

object_storage_client = oci.object_storage.ObjectStorageClient(config,signer=signer)

# Get the namespace
try:
    namespace = object_storage_client.get_namespace().data
    print("Object Storage Namespace:", namespace)
except oci.exceptions.ServiceError as e:
    print("Error fetching namespace:", e)