# Configure the Oracle Cloud Infrastructure provider to use Security Token authentication
provider "oci" { # Path to your OCI config file
    config_file_profile = "UPST"  # Use the default profile in the config file
    auth = "SecurityToken"
    region = "us-ashburn-1"  # Replace with your desired region
}