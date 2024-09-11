#!/usr/bin/env python3
import boto3
import json
import sys

def get_secret(secret_name, region_name="us-east-1"):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        # Retrieve the secret
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        
        # Decrypts secret using the associated KMS CMK.
        secret = get_secret_value_response['SecretString']
        
        return json.loads(secret)

    except Exception as e:
        print(f"Error retrieving secret: {str(e)}", file=sys.stderr)
        sys.exit(1)

def print_exports(secret_dict):
    # Print each key/value pair in export format for a shell
    for key, value in secret_dict.items():
        print(f"export {key}='{value}'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: eval `awsenv <secret_name>`", file=sys.stderr)
        sys.exit(1)
    
    secret_name = sys.argv[1]
    
    secret_dict = get_secret(secret_name)
    print_exports(secret_dict)