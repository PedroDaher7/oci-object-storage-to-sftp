import io
import json
import oci
from io import StringIO
import paramiko
from paramiko import Transport, SFTPClient, RSAKey
from fdk import response
import base64
from oci.object_storage import UploadManager
from oci.object_storage.transfer.constants import MEBIBYTE

# Retrieve secret
def read_secret_value(secret_client, secret_id):
    response = secret_client.get_secret_bundle(secret_id)
    base64_secret_content = response.data.secret_bundle_content.content
    base64_secret_bytes = base64_secret_content.encode("ascii")
    base64_message_bytes = base64.b64decode(base64_secret_bytes)
    secret_content = base64_message_bytes.decode("ascii")
    return secret_content

def handler(ctx, data: io.BytesIO = None):
    signer = oci.auth.signers.get_resource_principals_signer()

    body = json.loads(data.getvalue())
    host = "your_host"  # Placeholder for host
    username = "your_username"  # Placeholder for username
    source_file = "Source_File_Path" + body["data"]["resourceName"] # Placeholder for Path the File is going to
    bucket = body["data"]["additionalDetails"]["bucketName"]
    object_name = body["data"]["resourceName"]
    operation = "GET"
    secret_id = "your_secret_ocid"  # Placeholder for secret OCID

    print("host: " + host)
    print("username: " + username)
    print("source_file: " + source_file)
    print("bucket: " + bucket)
    print("object_name: " + object_name)
    print("operation: " + operation)
    print("secret_id: " + secret_id)

    if (
        host is None
        or username is None
        or source_file is None
        or bucket is None
        or object_name is None
        or secret_id is None
    ):
        resp_data = {
            "status": "407",
            "info": "One of the items in the input payload was not supplied; host, user, sftp_file, bucket, object_name, secret",
        }
        return response.Response(
            ctx, response_data=resp_data, headers={"Content-Type": "application/json"}
        )

    if operation is None:
        operation = "PUT"

    try:
        # In the base case, configuration does not need to be provided as the region and tenancy are obtained from the InstancePrincipalsSecurityTokenSigner
        identity_client = oci.identity.IdentityClient(config={}, signer=signer)
        # Get instance principal context
        print("Reading secret from the vault", flush=True)
        secret_client = oci.secrets.SecretsClient(config={}, signer=signer)
        secret_contents = read_secret_value(secret_client, secret_id)
        print("Read secret from the vault", flush=True)

        password = secret_contents
        port = 22

        print("Connecting to host", flush=True)
        con = Transport(host, port)
        con.connect(None, username=username, password=password)
        sftp = SFTPClient.from_transport(con)
        # sftp.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            object_storage_client = oci.object_storage.ObjectStorageClient(
                config={}, signer=signer
            )
            namespace = object_storage_client.get_namespace().data
            file1 = object_storage_client.get_object(namespace, bucket, object_name)
            print("Get object from Object Storage.", flush=True)
            with sftp.file(source_file, "Source_File") as f: # Change the Source File here
                for chunk in file1.data.raw.stream(1024 * 1024, decode_content=False):
                    print("Writing data from Object Storage to host.", flush=True)
                    f.write(chunk)

            f.close()
            sftp.close()
            resp_data = {"status": "200"}
        except Exception as err:
            print(err)
            resp_data = {"status": "405", "info": str(err)}
            return response.Response(
                ctx,
                response_data=resp_data,
                headers={"Content-Type": "application/json"},
            )
    finally:
        print("File uploaded successfully")
    return response.Response(
        ctx,
        response_data=resp_data,
        headers={"Content-Type": "application/json"},
    )
