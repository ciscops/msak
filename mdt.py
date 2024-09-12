#!/usr/bin/env python3
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import aiohttp
import asyncio
import json
import argparse
import os
import yaml
import logging
import re
import requests
import time
import pprint
import sys
import traceback
from dictdiffer import diff
import jsonschema
from jsonschema import validate
from aiohttp.client_exceptions import ClientError
import pandas as pd

CONFIG_FILES = ['/etc/meraki/meraki_inventory.yml', '/etc/ansible/meraki_inventory.yml']
OPENAPI_SPEC_FILE = 'meraki-openapi-3.0.1.json'
API_MAX_RETRIES             = 3
API_CONNECT_TIMEOUT         = 60
API_TRANSMIT_TIMEOUT        = 60
API_STATUS_RATE_LIMIT       = 429
API_RETRY_DEFAULT_WAIT      = 3

PRODUCT_TYPES = [
        'appliance',
        'switch',
        'wireless',
        'sensor',
        'camera',
        'cellularGateway'
]

index_lookup = {
    "/networks/{networkId}/switch/accessPolicies": "accessPolicyNumber",
    "/networks/{networkId}/wireless/ssids": "number",
    "/networks/{networkId}/groupPolicies": "groupPolicyId",
    "/networks/{networkId}/appliance/vlans": "vlanId",
    "/devices/{serial}/switch/routing/interfaces": "interfaceId",
    "/networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces": "interfaceId",
    "/networks/{networkId}/vlanProfiles": "iname",
    "/devices/{serial}/switch/routing/staticRoutes": "staticRouteId",
    "/networks/{networkId}/switch/stacks/{switchStackId}/routing/staticRoutes": "staticRouteId",
    "/devices/{serial}/switch/ports": "portID"
}


template_schemas = {
    "/networks/{networkId}/wireless/ssids/{number}": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The name of the SSID"
                        },
                        "enabled": {
                            "type": "boolean",
                            "description": "Whether or not the SSID is enabled"
                        }
                    }
            }
}

def default_api_handler(path, api_key, base_url, payload, **kwargs):
    event_handler("info", f"Default handler: {path}")
    index_key = None
    #
    # See if we can figure out what this data structure using for its index
    #
    if isinstance(payload, list):
        #
        # If this is a list, look to see if the index is known
        #
        if path in index_lookup:
            index_key = index_lookup[path]
    if index_key == None:
        event_handler("error", f"Unable to process path {path}: Index not found.")
    else:
        #
        # First we need to see what data is there to see if we need to put or post
        #
        data = meraki_read_path(path, api_key, base_url, **kwargs)
        existing_data_map = {}
        for item in data:
            if "name" in item:
                existing_data_map[item["name"]] = item
            else:
                event_handler("error", f"Unable to process path {path}: Name not found.")
                return ({})
        for item in payload:
            if "radiusServers" in item:
                for server in item["radiusServers"]:
                    server.pop("serverId", None)
                    server["secret"] = "ChangeMe"
            if "radiusAccountingServers" in item:
                for server in item["radiusAccountingServers"]:
                    server.pop("serverId", None)
                    server["secret"] = "ChangeMe"  
            if item["name"] in existing_data_map:
                #
                # The item exists, so we need to call the api's per-item form
                #
                item_path = path + '/{' + index_key + '}'
                # Use the index_key from the current data instead of the imported data
                kwargs[index_key] = existing_data_map[item["name"]][index_key]
                result = meraki_write_path(item_path, args.api_key, base_url, item, **kwargs)
            else:
                #
                # The item does not exist, so we create it with the same api
                #
                result = meraki_write_path(path, args.api_key, base_url, item, **kwargs)

    return (result)

def noop(path, payload):
    event_handler("warning", f"{path} is currently unsupported")

def wireless_handler(path, payload):
    event_handler("info", f"Wireless hander: {path}")
    # if payload["authMode"] == "psk":
    #     payload["psk"] = "ChangeMe"
    if "radiusServers" in payload:
        for server in payload["radiusServers"]:
            server["secret"] = "ChangeMe"
            if "openRoamingCertificateId" in server and server["openRoamingCertificateId"] == None:
                server.pop("openRoamingCertificateId")
    if "radiusAccountingServers" in payload:
        for server in payload["radiusAccountingServers"]:
                server["secret"] = "ChangeMe"
    if "splashUrl" in payload and payload["splashUrl"] == None:
        payload = {}
    return (payload)

def switchport_handler(path, api_key, base_url, payload, **kwargs):
    event_handler("info", f"Switchport hander: {path}")
    for item in payload and item["profile"]["enabled"] == True:
        if "profile" in item:
            # The API does not allow certain attributes when assocaited with a port profile
            if args.ignore_profile:
                item["profile"]["enabled"] = False
            else:
                item.pop("tags", None)
                item.pop("accessPolicyNumber", None)
                item.pop("accessPolicyType", None)
                item.pop("allowedVlans", None)
                item.pop("daiTrusted", None)
                item.pop("name", None)
                item.pop("poeEnabled", None)
                item.pop("rstpEnabled", None)
                item.pop("stpGuard", None)
                item.pop("type", None)
                item.pop("udld", None)
                item.pop("vlan", None)
                item.pop("voiceVlan", None)
                item.pop("isolationEnabled", None)

        item_path = f"{path}/{item['portId']}"
        verb, schema, responses = get_schema(path + "/{portId}", "write", **kwargs)
        kwargs['portId'] = item['portId']
        kwargs['schema'] = schema
        kwargs['verb'] = verb
        result = meraki_write_path(item_path, api_key, base_url, item, **kwargs)
    return (result)

def switch_acl_handler(path, payload):
    event_handler("debug", "Called switch_acl_handler")
    new_payload = {
        "rules": []
    }
    #
    # Need to remove the default rule
    #
    for rule in payload["rules"]:
        if rule["comment"] != "Default rule":
            new_payload["rules"].append(rule)
    return (new_payload)

def l3FirewallRules_handler(path, payload):
    event_handler("debug", "Called switch_acl_handler")
    new_payload = {
        "rules": [],
        "allowLanAccess": True
    }
    #
    # Need to remove the default rule
    #
    for rule in payload["rules"]:
        if rule["comment"] == "Wireless clients accessing LAN":
            if rule["policy"] == "deny":
                new_payload["allowLanAccess"] = False
        elif rule["comment"] == "Default rule":
            pass
        else:
            new_payload["rules"].append(rule)
    return (new_payload)

api_path_handlers = {
    "/networks/{networkId}/wireless/ssids/{number}": wireless_handler,
    "/networks/{networkId}/wireless/ssids/{number}/splash/settings": wireless_handler,
    "/networks/{networkId}/wireless/ssids/{number}/firewall/l3FirewallRules": l3FirewallRules_handler,
    "/networks/{networkId}/switch/accessControlLists": switch_acl_handler

#   "/devices/{serial}/switch/ports": switchport_handler,
#   "/networks/{networkId}/switch/accessPolicies": default_api_handler,
#   "/networks/{networkId}/groupPolicies": default_api_handler,
#   "/networks/{networkId}/appliance/vlans": default_api_handler,
#   "/devices/{serial}/switch/routing/interfaces": default_api_handler,
#   "/networks/{networkId}/vlanProfiles": default_api_handler,
#   "/devices/{serial}/switch/routing/staticRoutes": default_api_handler,
#   "/networks/{networkId}/wireless/ssids/{number}/splash/settings": noop,
#   "/networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces": default_api_handler,
#   "/networks/{networkId}/switch/stacks/{switchStackId}/routing/staticRoutes": default_api_handler,
#   "/networks/{networkId}/snmp": noop,
#   "/networks/{networkId}/wireless/electronicShelfLabel": noop,
#   "/devices/{serial}/wireless/electronicShelfLabel": noop,
#   "/networks/{networkId}/webhooks/payloadTemplates": noop,
#   "/devices/{serial}/appliance/dhcp/subnets": default_api_handler,
#   "/networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces/{interfaceId}/dhcp": noop,
#   "/devices/{serial}/switch/routing/interfaces/{interfaceId}/dhcp": noop,
#   "/networks/{networkId}/wireless/rfProfiles": noop,
#   "/networks/{networkId}/wireless/ssids/{number}/splash/settings": noop,
#   "/networks/{networkId}/wireless/ssids/{number}/hotspot20": noop
}

def get_spec_path(path):
    if path in openapi_spec['paths']:
        event_handler("debug", f"Found {path} in spec")
        return path
    else:
        event_handler("debug", f"Finding match for {path} in spec")
        # Sort keys by length in descending order to match the longest path first
        sorted_keys = sorted(index_lookup.keys(), key=len, reverse=True)
        new_path = None
        for key in sorted_keys:
            if path.startswith(key):
                event_handler("debug", f"Found {key} as best match for {path}.")
                # Get the value from index_lookup for the matched key
                index = index_lookup[key]

                # Create a regex pattern to identify the portion to be replaced
                key_with_param = re.sub(r'\{[^}]+\}', '[^/]+', key) + r'/([^/]+)'

                # Replace the first path component after the match with the placeholder value
                new_path =  re.sub(key_with_param, key + r'/{' + index + r'}', path)
                break
        # Return the original path if no match is found
        if new_path:
            return get_spec_path(new_path)
        else:
            event_handler("error", f"Could not find match for {path}")
            return None


def get_schema(spec_path, operation, **kwargs):
    spec_path_data = openapi_spec['paths'][spec_path]
    if operation == 'write':
        if 'put' in spec_path_data:
            verb = 'put'   
            schema = spec_path_data[verb]["requestBody"]["content"]["application/json"]["schema"]
            responses = [int(item) for item in spec_path_data[verb]["responses"].keys()]
        elif 'post' in spec_path_data:
            verb = 'post'
            if "requestBody" in spec_path_data[verb]:
                schema = spec_path_data[verb]["requestBody"]["content"]["application/json"]["schema"]
            else:
                schema = {}
            responses = [int(item) for item in spec_path_data[verb]["responses"].keys()]
        else:
            event_handler("warning", f"{path}, Error: Readonly path")
            verb = None
            schema = {}
    elif operation == 'read':
        if 'get' in spec_path_data:
            verb = 'get'   
            schema = {}
            responses = [int(item) for item in spec_path_data[verb]["responses"].keys()]
        else:
            event_handler("warning", f"{path}, Error: Write-only path")
            verb = None
            schema = {}
            responses = {}
    else:
        event_handler("critical", f"Unknown schema operation {operation}.")
        exit (1)

    if "bound_to_template" in kwargs and kwargs["bound_to_template"] == True:
        #
        # If this is for a template, we override the template schema, but keep the verb
        if path in template_schemas:
            schema = template_schemas[path]
        else:
            schema = {}

    return (verb, schema, responses)

def is_invalid_payload(data, schema):
    try:
        validate(instance=data, schema=schema)
        return None
    except jsonschema.exceptions.ValidationError as err:
        return err.message

def remove_null_values(d):
    # Create a copy of the dictionary to avoid modifying the original during iteration
    keys_to_delete = []

    for key, value in d.items():
        if isinstance(value, dict):
            # Recurse into the nested dictionary
            remove_null_values(value)
            # If the nested dictionary is empty after recursion, mark the key for deletion
            if not value:
                keys_to_delete.append(key)
        elif value is None:
            # Mark keys with null values for deletion
            keys_to_delete.append(key)

    # Remove keys marked for deletion
    for key in keys_to_delete:
        del d[key]

def meraki_request(url, api_key, verb="get", responses=[200], payload={}, parameters=[], **kwargs):
    headers = {
        'Authorization': f'Bearer {api_key}'
    }      
    while True:
        try:
            if verb == "get":
                parameter_string = ""
                for parameter in parameters:
                    if parameter_string == "":
                        parameter_string = '?' + parameter
                    else:
                        parameter_string = parameter_string + '&' + parameter           
                response = requests.get(url + parameter_string,
                        headers =   headers,
                        timeout =   (API_CONNECT_TIMEOUT, API_TRANSMIT_TIMEOUT)
                    )                
            elif verb == "put":
                response = requests.put(url,
                        headers =   headers,
                        json    =   payload,
                        timeout =   (API_CONNECT_TIMEOUT, API_TRANSMIT_TIMEOUT)
                    )
            else:
                response = requests.post(url,
                        headers =   headers,
                        json    =   payload,
                        timeout =   (API_CONNECT_TIMEOUT, API_TRANSMIT_TIMEOUT)
                    )
            
            # Check the status code
            if response.status_code in responses:
                if response.status_code == 204:
                    return {}
                else:
                    return (response.json())
            # elif response.status_code == 401:
            #     event_handler("critical", f"{url}, Error 401: Unauthorized access - check your API key.")
            #     exit (1)
            # elif response.status_code == 404:
            #     event_handler("critical", f"{url}, Error 404: The requested resource was not found.")
            #     exit (1)
            elif response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after is not None:
                    wait_retry = int(retry_after)
                else:
                    wait_retry = API_RETRY_DEFAULT_WAIT             
                event_handler("warning", f"Error 429: Rate limit exceeded. Retrying in {wait_retry} seconds...")
                time.sleep(wait_retry)
            else:
                event_handler("error", f"{url}, Error {response.status_code} ({response.reason}): {response.text}")
                return None
        
        except requests.exceptions.RequestException as e:
            event_handler("critical", f"An error occurred while making the request: {e}")
            exit (1)    

def meraki_read_path(path, api_key, base_url, **kwargs) -> dict | None:
    # Get the spec path that corresponds to this path
    spec_path = get_spec_path(path)
    if spec_path == None:
        event_handler("error", f"Could not find {path} in spec.")
        return (None)
    
    if 'schema' in kwargs:
        schema = kwargs['schema']
        verb = 'get'
    else:
        verb, schema, responses = get_schema(spec_path, "read", **kwargs)
    url = f"{base_url}" + path.format(**kwargs).removesuffix('/')
    if verb == None:
        event_handler("warning", f"{path} is write-only")
        return None
    return meraki_request(url, api_key, responses=responses, **kwargs)


def meraki_write_path(path, api_key, base_url, raw_payload, **kwargs) -> dict | None:
    change_needed = True
    path = path.removesuffix('/')
    # Get the spec path that corresponds to this path
    spec_path = get_spec_path(path)
    if spec_path == None:
        event_handler("error", f"Could not find {path} in spec.")
        return (None)

    if 'schema' in kwargs:
        schema = kwargs['schema']
        verb = kwargs['verb']
    else:
        verb, schema, responses = get_schema(spec_path, "write", **kwargs)

    full_path = path.format(**kwargs)
    url = f"{base_url}" + full_path

    if "bound_to_template" in kwargs and kwargs["bound_to_template"] == True and schema == {}:
        event_handler("info", f"Network {kwargs['networkId']} is bound to a template. Ignoring {full_path}")
        return {}

    # Reduce the payload down to what is in the schema for the put/post operation 
    filtered_payload = filter_data_by_schema(raw_payload, schema)

    # if reason := is_invalid_payload(payload, schema):
    #     event_handler("error", f"Invalid payload for {full_path}: {reason}")
    #     if args.log_level == "DEBUG":
    #         pprint.pp(filtered_payload)
    #     return {}

    if hasattr(args, 'diff') and args.diff == True:
        show_diff = True
    else:
        show_diff = False

    #
    # Get the current data
    #
    current_data = meraki_read_path(path, args.api_key, base_url, **kwargs)
    if (current_data != None):
        filtered_current_data = filter_data_by_schema(current_data, schema)
        #
        # Diff the current state and the proposed state
        #
        diff_dict = list(diff(filtered_current_data, filtered_payload))
    else:
        diff_dict = []
        event_handler("warning", f"Unable to get {full_path}")

    # Do this after the diff because it can make it look like there is a change when there is not
    if spec_path in api_path_handlers:
        processed_payload = api_path_handlers[spec_path](path, filtered_payload)
    else:
        processed_payload = filtered_payload

    # filtered_payload = remove_null_values(filtered_payload)

    if diff_dict and processed_payload:
        change_needed = True
        if show_diff:
            print(color_message(path.format(**kwargs), "yellow"))
            print ("Current:")
            pprint.pp(filtered_current_data)
            print ("New:")
            pprint.pp(filtered_payload)
            print ("Diff:")
            pprint.pp(diff_dict)
    else:
        change_needed = False
        if show_diff:
            print(color_message(path.format(**kwargs), "green"))

    if args.dry_run or (filtered_payload == {} and schema != {}):
        change_needed = False

    # Override the diff and always write the data
    if hasattr(args, 'always_write') and args.always_write == True:
        change_needed = True

    if change_needed:
        # if args.log_level == "DEBUG":
        print(f"Writing to {url}")
        pprint.pp(filtered_payload)
        return meraki_request(url, api_key, payload=processed_payload, verb=verb, responses=responses, **kwargs)
    else:
        return {}

async def merakiBulkGet(session, path, api_key, base_url, semaphore):
    """
    Fetches the content of the URL using a GET request with headers.

    Parameters:
    - session (aiohttp.ClientSession): The aiohttp session.
    - url (str): The URL to fetch.
    - headers (dict): The headers to include in the request.
    - path (str): The API path to structure the results.
    - semaphore (asyncio.Semaphore): The semaphore to limit concurrent requests.

    Returns:
    - tuple: A tuple containing the path and its response.
    """
    headers = {
        'Authorization': f'Bearer {api_key}'
    }  
    url = f"{base_url}" + path
    retry = 0
    async with semaphore:
        while True:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        if response.headers['Content-Type'] == 'application/json':
                            return (path, await response.json())
                        else:
                            return (path, await response.json(encoding="utf-8"))
                    elif response.status == 429:
                        retry_after = response.headers.get("Retry-After")
                     
                        if retry_after is not None:
                            wait_retry = int(retry_after)
                        else:
                            wait_retry = API_RETRY_DEFAULT_WAIT
                        event_handler("debug", f"Received {response.status} status code. Retrying url {url} in {wait_retry} seconds...")
                    elif response.status in [400, 404]:
                        event_handler("error", f"{url}, Error {response.status} ({response.reason})")
                        return (path, {})  
                    else:
                        event_handler("error", f"{url}, Error {response.status} ({response.reason}): {response.text}")
                        return (path, {})
                retry = retry + wait_retry
                await asyncio.sleep(retry)
            except aiohttp.ClientError as e:
                event_handler("error", f"An error occurred: {str(e)}")
            except asyncio.TimeoutError:
                event_handler("error", "The request timed out.")
            except Exception as e:
                event_handler("error", f"An unexpected error occurred: {str(e)}")

async def fetch_all_paths(paths, headers, base_url, max_concurrent_requests):
    """
    Fetches the content of all URLs asynchronously with headers, limiting concurrent requests.

    Parameters:
    - urls (list): A list of tuples containing URLs and paths to fetch.
    - headers (dict): The headers to include in the request.
    - max_concurrent_requests (int): The maximum number of concurrent requests allowed.

    Returns:
    - dict: A dictionary containing all paths and their responses.
    """
    semaphore = asyncio.Semaphore(max_concurrent_requests)
    async with aiohttp.ClientSession() as session:
        tasks = [merakiBulkGet(session, path, headers, base_url, semaphore) for path in paths]
        result_dict = {}
        for task in asyncio.as_completed(tasks):
            # as_completed returns an iterator, so we just have to await the iterator and not call it
            (path, result) = await task
            match = re.match('^/([^/]+)/([^/]+)(/[^{}]*)?$', path)
            if result:
                if match.group(1) not in result_dict:
                    result_dict[match.group(1)] = {}
                if match.group(2) not in result_dict[match.group(1)]:
                    result_dict[match.group(1)][match.group(2)] = {}
                    result_dict[match.group(1)][match.group(2)]['paths'] = {}
                result_dict[match.group(1)][match.group(2)]['paths'][match.group(3)] = result
    return result_dict

def filter_data_by_schema(data, schema):
    """Recursively filters the data to match the structure defined by the schema."""
    if 'properties' in schema:
        filtered_data = {}
        for key, subschema in schema['properties'].items():
            if key in data:
                filtered_data[key] = filter_data_by_schema(data[key], subschema)
        return filtered_data
    elif 'items' in schema and isinstance(data, list):
        return [filter_data_by_schema(item, schema['items']) for item in data]
    else:
        return data

def print_tabular_data(data, columns_to_display):
    """
    Formats and prints JSON-like data in a tabular format with left-justified headers and data.
    
    Args:
        data (list of dict): The input data to be formatted and printed.
        columns_to_display (list of str): The columns to be printed.
    """
    # Convert the list of dictionaries to a pandas DataFrame
    df = pd.DataFrame(data)

    # Calculate the max width for each column to apply uniform left-justification
    max_col_widths = {col: max(df[col].astype(str).map(len).max(), len(col)) for col in columns_to_display}

    # Left-justify column titles and data with custom formatting
    formatted_rows = []

    # Format the header row
    header_row = '  '.join([col.ljust(max_col_widths[col]) for col in columns_to_display])
    formatted_rows.append(header_row)

    # Format the data rows
    for _, row in df[columns_to_display].iterrows():
        formatted_row = '  '.join([str(row[col]).ljust(max_col_widths[col]) for col in columns_to_display])
        formatted_rows.append(formatted_row)

    # Print the formatted table
    print('\n'.join(formatted_rows))


async def export_command(args):
    #
    # Build the list of paths that we want to export
    #
    api_paths = []
    network_ids = []
    serial_numbers = []
    config_template_ids = []
    stacks_by_network = {}
    #
    # Export Openapi Spec
    #
    # if args.context == "spec":
    #     spec = meraki_read_path(f"/organizations/{args.org_id}/openapiSpec", headers, args.base_url)
    #     export_file(args.output_file, spec)
    #     exit (0)
    parameters = []
    if args.networks:
        network_ids = args.networks
        networks = []
        template_ids =[]
        for network_id in network_ids:
            network = meraki_read_path("/networks/{networkId}", args.api_key, args.base_url, networkId=network_id)
            networks.append(network)
            parameters.append(f"networkIds[]={network_id}")

            #
            # Collect the config templates that the networks are bound to
            #                
            if "isBoundToConfigTemplate" in network and network["isBoundToConfigTemplate"] == True:
                if network["configTemplateId"] not in template_ids:
                    template_ids.append(network["configTemplateId"])
        network_ids.extend(template_ids)
    else:
        networks = meraki_read_path("/organizations/{organizationId}/networks", args.api_key, args.base_url, organizationId=args.org_id)
        # List comprehension to extract serial numbers
        network_ids = [item["id"] for item in networks]
        #
        # Get all of the templates for export
        #
        config_template_templates = meraki_read_path("/organizations/{organizationId}/configTemplates", args.api_key, args.base_url, organizationId=args.org_id)
        # List comprehension to extract serial numbers
        network_ids = network_ids + [item["id"] for item in config_template_templates]
    event_handler("info", f"Exporting networks {network_ids}")   
    #
    # Get all of the devices for export
    #
    devices = meraki_read_path("/organizations/{organizationId}/devices", args.api_key, args.base_url, organizationId=args.org_id, parameters=parameters)
    # List comprehension to extract serial numbers
    serial_numbers = [item["serial"] for item in devices]
    for network in networks:
        #
        # Get all of the switch stacks for export
        #
        switch_stacks = meraki_read_path("/networks/{networkId}/switch/stacks", args.api_key, args.base_url, networkId=network["id"])
        if switch_stacks:
            stacks_by_network[network["id"]] = {}
            for stack in switch_stacks:
                switch_stacks_interfaces = meraki_read_path("/networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces", args.api_key, args.base_url, networkId=network["id"], switchStackId=stack["id"])
                stack_interface_ids = []
                for interface in switch_stacks_interfaces:
                    stack_interface_ids.append(interface["interfaceId"])
                stacks_by_network[network["id"]][stack["id"]] = stack_interface_ids
    #
    # Find all of the paths out of the spec that apply to what we are trying to export
    #
    for path, verbs in openapi_spec['paths'].items():
        # Only get paths that we can write something back to.
        path_exported = False
        # if args.full_export:
        #     pass
        if path in config["api_path_exlude"]:
            event_handler("debug", f"{path} is excuded")
            continue
        elif 'get' not in verbs.keys():
            event_handler("debug", f"{path} is write-only")
            continue
        elif len(verbs) == 1 and "get" in verbs:
            event_handler("debug", f"{path} is read-only")
            continue               
        else:
            #
            # /networks/{networkId}: We need to itterate over all of the networks
            #
            if match := re.match('^/networks/{networkId}/?(.*)$', path):
                base_path = "/networks/{networkId}"
                sub_path = "/" + match.group(1)
                for network_id in network_ids:
                    #
                    # Wireless SSIDS
                    #
                    if match := re.match('^/wireless/ssids/{number}(/.*)?$', sub_path):
                        if match.group(1):
                            wireless_path = match.group(1)
                        else:
                            wireless_path = ""
                        if match := re.match('^/[^{}]+{', wireless_path):
                            # Unhandled paths because they need more dereferencing
                            path_exported = False
                        else:
                            path_exported = True
                            # We need to have one of each of these paths per device
                            for number in range(0, 14):
                                api_paths.append(f"/networks/{network_id}/wireless/ssids/{number}" + wireless_path)
                    #
                    # Switch Stacks
                    # 
                    elif match := re.match('^/switch/stacks/{switchStackId}(/.+)?$', sub_path):
                        if network_id not in stacks_by_network:
                            # There are no stacks
                            continue
                        if match.group(1):
                            stack_path = match.group(1)
                        else:
                            stack_path = ""
                        if match := re.match('^/[^{}]+{', stack_path):
                            # Unhandled paths because they need more dereferencing
                            path_exported = False
                        else:
                            path_exported = True
                            # We need to have one of each of these paths per device
                            for stack_id, stack_interfaces in stacks_by_network[network_id].items():
                                if match := re.match('^/routing/interfaces/{interfaceId}(/.*)?$', stack_path):
                                    if match.group(1):
                                        if match.group(1) == "/dhcp":
                                            for interface_id in stack_interfaces:
                                                api_paths.append(f"/networks/{network_id}/switch/stacks/{stack_id}/routing/interfaces/{interface_id}/dhcp")
                                        else:
                                            api_paths.append(f"/networks/{network_id}/switch/stacks/{stack_id}/routing/interfaces/{interface_id}" + match.group(1))
                                else:
                                    api_paths.append(f"/networks/{network_id}/switch/stacks/{stack_id}" + stack_path)
                    elif match := re.match('^/[^{}]+{', sub_path):
                        # Unhandled paths because they need more dereferencing
                        path_exported = False
                    else:
                        path_exported = True
                        api_paths.append(f"/networks/{network_id}" + sub_path)
            #   
            # /organizations/{args.org_id}
            #
            elif match := re.match('^/organizations/{organizationId}/?(.*)$', path):
                sub_path = '/' + match.group(1)
                if match := re.match('^/[^{}]+{', sub_path):
                    # Unhandled paths because they need more dereferencing
                    path_exported = False
                else:
                    path_exported = True    
                    api_paths.append(f"/organizations/{args.org_id}" + sub_path)

            # match = re.match('^/([^/]+)/{[^{}]+}/?([^{}]*)$', path)
            # if match:
            #     path_exported = True
            #     sub_path = '/' + match.group(2)
            #     if match.group(1) == "networks":
            #         for network_id in network_ids:
            #             api_paths.append(f"/networks/{network_id}" + sub_path)                        
            #         for config_template_id in config_template_ids:
            #             api_paths.append(f"/networks/{config_template_id}" + sub_path)
                    
            #
            # /devices/{serial}
            #
            elif match := re.match('^/devices/{serial}/?(.*)$', path):
                sub_path = '/' + match.group(1)
                if match := re.match('^/[^{}]+{', sub_path):
                    # Unhandled paths because they need more dereferencing
                    path_exported = False
                elif serial_numbers:                   
                    path_exported = True
                    # We need to have one of each of these paths per device
                    for serial in serial_numbers:
                        api_paths.append(f"/devices/{serial}" + sub_path)
            #
            # "/devices/{serial}/switch/routing/interfaces/{interfaceId}"
            #
        if not path_exported:
            event_handler("warning", f"{path} not exported")
    #
    # Make a bulk request to the async function
    #
    result_dict = await fetch_all_paths(api_paths, args.api_key, args.base_url, args.max_concurrent_requests)
    if args.output_file:
        output_file = args.output_file
    else:
        if args.networks and len(args.networks) == 1:
            output_file = f"{args.org_id}_{args.networks[0]}.json"
        else:
            output_file = f"{args.org_id}.json"

    with open(output_file, 'w') as file:
        result_dict['errors'] = error_log
        json.dump(result_dict, file, indent=4)
    event_handler("info", f"Results saved to {output_file}")


def import_file(filename):
        event_handler("info", f"Reading {filename}...")
        try:
            with open(filename, 'r') as file:
                if filename.endswith('json'):
                    return json.load(file)
                else:
                    return yaml.safe_load(file)
        except FileNotFoundError:
            event_handler("critical", f"Error: The file '{args.input_file}' was not found.")
            exit (1)
        except json.JSONDecodeError:
            event_handler("critical", f"Error: The file '{args.input_file}' contains invalid JSON.")
            exit (1)
        except PermissionError:
            event_handler("critical", f"Error: You do not have permission to read the file '{args.input_file}'.")
            exit (1)
        except Exception as e:
            event_handler("critical", f"An unexpected error occurred: {str(e)}")
            exit (1)

def export_file(filename, contents):
    event_handler("info", f"Writing {filename}...")
    with open(filename, 'w') as file:
        json.dump(contents, file, indent=4)

def show_command(args):
    parameters = []
    if hasattr(args, 'tags') and args.tags:
        for tag in args.tags: 
            parameters.append(f"tags[]={tag}")

    if args.show_command == 'networks':
        networks = meraki_read_path("/organizations/{organizationId}/networks", args.api_key, args.base_url, organizationId=args.org_id)
        if args.json:
            pprint.pp(networks)
        else:
            print_tabular_data(networks, ['id', 'name', 'productTypes', 'timeZone', 'tags'])      
    elif args.show_command == 'organizations':
        organizations = meraki_read_path("/organizations", args.api_key, args.base_url)
        if args.json:
            pprint.pp(organizations)
        else:
            print_tabular_data(organizations, ['id', 'name'])       
    elif args.show_command == 'devices':
        devices = meraki_read_path("/organizations/{organizationId}/devices", args.api_key, args.base_url, organizationId=args.org_id)
        if args.json:
            pprint.pp(devices)
        else:
            print_tabular_data(devices, ['name', 'serial', 'mac', 'model', 'networkId', 'tags'])
    elif args.show_command == 'templates':
        templates = meraki_read_path("/organizations/{organizationId}/configTemplates", args.api_key, args.base_url, organizationId=args.org_id)
        if args.json:
            pprint.pp(templates)
        else:
            print_tabular_data(templates, ['id', 'name', 'productTypes', 'timeZone'])
    elif args.show_command == 'me':
        organizations = meraki_read_path("/organizations", args.api_key, args.base_url)
        me = meraki_read_path("/administered/identities/me", args.api_key, args.base_url)
        org_name = "Unknown"
        for org in organizations:
            if org["id"] == args.org_id:
                org_name = org["name"]

        print (f"Name:            {me['name']}")
        print (f"Email:           {me['email']}")
        print (f"MERAKI_ORG_ID:   {args.org_id} ({org_name})")
        print (f"MERAKI_BASE_URL: {args.base_url}")
    else:
        event_handler("critical", f"Unknown show command {args.show_command}")

def import_command(args):
    #
    # Open the file that we are trying to import
    #
    import_data = import_file(args.input_file)

    if len(import_data["organizations"]) == 0:
        event_handler("critical", "Organization data missing from import file")
        exit (1)
    elif len(import_data["organizations"]) > 1 and args.source_org_id == None:
        event_handler("critical", "Multiple Organizations in import file. `--source-org-id` must be specified.")
        exit (1)
    elif len(import_data["organizations"]) == 1 and args.source_org_id == None:
        source_org_id = next(iter(import_data["organizations"]))
    else:
        source_org_id = args.source_org_id

    if args.import_command == "templates":
        source_config_templates = import_data["organizations"][source_org_id]["paths"]["/configTemplates"]
        target_config_templates = meraki_read_path("/organizations/{organizationId}/configTemplates", args.api_key, args.base_url, organizationId=args.org_id)
        # target_config_template_names = [item["name"] for item in target_config_templates]
        #
        # Create the Templates if the do not already exist
        #
        for source_config_template in source_config_templates:
            if source_config_template["id"] in import_data["networks"]:                
                target_config_template_id = None
                for target_config_template in target_config_templates:
                    if target_config_template["name"] == source_config_template["name"]:
                        event_handler("debug", "Found existing template {source_config_template['name']} ({target_config_template['id']}).")
                        target_config_template_id = target_config_template["id"]
                #
                # If no template was found by that name, it needs to be created
                #
                if target_config_template_id == None:
                    event_handler("info", f"Creating config template {source_config_template['name']}")
                    result = meraki_write_path("/organizations/{organizationId}/configTemplates", args.api_key, args.base_url, source_config_template, organizationId=args.org_id)
                    if result and "id" in result:
                        target_config_template_id = result["id"]
                    else:
                        event_handler("critical", f"Error creating template {source_config_template['name']}")
                        exit (1)
                #
                # Load/Update the template data
                #
                source_config_template_data = import_data["networks"][source_config_template["id"]]["paths"]
                for sub_path, config_template_data in source_config_template_data.items():
                    path = "/networks/{networkId}" + sub_path
                    meraki_write_path(path, args.api_key, args.base_url, config_template_data, networkId=target_config_template_id)
            else:
                event_handler("error", f"Skipping import of template {source_config_template['name']}({source_config_template['id']}) because it is not found in import data.")
    elif args.import_command == "networks":     
        target_networks = meraki_read_path("/organizations/{organizationId}/networks", args.api_key, args.base_url, organizationId=args.org_id)
        if args.source_network_id in import_data["networks"]:
            #
            # Map the source network to the desintation network by name
            #
            bound_to_template = False    
            source_network_id = args.source_network_id
            source_network_data = import_data["networks"][source_network_id]['paths']['/']
            source_network_name = source_network_data['name']     
            target_network_id = None
            for target_network in target_networks:
                if target_network["name"] == source_network_name:
                    target_network_id = target_network["id"]

            if target_network_id == None:
                event_handler("info", f"Creating network {source_network_name}")
                result = meraki_write_path("/organizations/{organizationId}/networks", args.api_key, args.base_url, source_network_data, organizationId=args.org_id)
                if result and "id" in result:
                    target_network = result
                    target_network_id = target_network["id"]
                else:
                    event_handler("critical", f"Error creating network {source_network_name}")
                    exit (1)
            #
            # Bind the network to the template if present
            #
            if "configTemplateId" in source_network_data:
                bound_to_template = True
                #
                # Find the name of the template associated with the source network's config template
                #
                source_network_template_id = source_network_data["configTemplateId"]
                source_network_template_name = None
                source_network_templates = import_data["organizations"][source_org_id]["paths"]["/configTemplates"]
                for source_network_template in source_network_templates:
                    if source_network_template["id"] == source_network_template_id:
                        source_network_template_name = source_network_template["name"]
                if source_network_template_name == None:
                    event_handler("critical", f"Could not find name for template ID: {source_network_template_id} in org {args.org_id}")
                    exit (1)
                #
                # If we find the name, find the template in the target network with the same name
                #
                target_config_templates = meraki_read_path("/organizations/{organizationId}/configTemplates", args.api_key, args.base_url, organizationId=args.org_id)                    
                target_config_template_id = None
                for target_config_template in target_config_templates:
                    if target_config_template["name"] == source_network_template_name:
                        target_config_template_id = target_config_template["id"]
                if target_config_template_id == None:
                    event_handler("critical", f"Could not find template {source_network_template_name} in org {args.org_id}")
                    exit (1)     


                if "configTemplateId" in target_network and target_network["configTemplateId"] != target_config_template_id:
                    event_handler("error", f"Target network bound to wrong template ({target_config_template_id} != {target_network['configTemplateId']}). We need to unbind and rebind this template")
                elif "configTemplateId" in target_network and target_network["configTemplateId"] == target_config_template_id:
                    # No change needed
                    pass
                else:
                    #
                    # Bind the network to the template
                    # 
                    bind_request_payload = {
                        "configTemplateId": target_config_template_id,
                        "autoBind": False
                    }
                    event_handler("debug", f"Binding network {source_network_name} to template {source_network_template_name}")
                    meraki_write_path("/networks/{networkId}/bind", args.api_key, args.base_url, bind_request_payload, networkId=target_network_id)                                             
            #
            # Load/Update the network data
            #
            kwargs = {}
            kwargs["networkId"] = target_network_id
            kwargs["bound_to_template"] = bound_to_template
            source_network_paths = import_data["networks"][source_network_id]["paths"]
            if "/switch/stacks" in source_network_paths and source_network_paths["/switch/stacks"]:
                # The source network had switch stacks, so we need to map them to the ones in the new network
                #
                # Get all of the switch stacks in the target network for mapping
                #
                target_stack_map = {} # by Name
                source_stack_map = {} # by Id
                target_switch_stacks = meraki_read_path("/networks/{networkId}/switch/stacks", args.api_key, args.base_url, networkId=target_network_id)

                for stack in target_switch_stacks:
                    target_stack_map[stack["name"]] = stack
                for stack in source_network_paths["/switch/stacks"]:
                    if stack["name"] in target_stack_map:
                        source_stack_map[stack["id"]] = target_stack_map[stack["name"]]["id"]
                    else:
                        event_handler("error", f"Mapping for source stack {stack['name']} ({stack['id']}) not found")
            for sub_path, network_data in source_network_paths.items():
                if args.product_types and (sub_path.split('/')[1] in PRODUCT_TYPES and sub_path.split('/')[1] not in args.product_types):
                    logging.debug(f"Skipping {sub_path}")
                    continue 
                path = "/networks/{networkId}" + sub_path
                #
                # Handle the endpoints for each of the SSIDs
                #
                if wireless_ssid_match := re.match('^/networks/{networkId}/wireless/ssids/([0-9]+)/([^{}]+)$', path):
                    kwargs["number"] = wireless_ssid_match.group(1)
                    path = "/networks/{networkId}/wireless/ssids/{number}/" + wireless_ssid_match.group(2)
                #
                # Handle the Stacks
                #
                stack_match = re.match('^/networks/{networkId}/switch/stacks/([^/]+)/?([^{}]*)$', path)
                if stack_match:
                    source_switchStackId = stack_match.group(1)
                    print (f"Stack: {source_switchStackId}")
                    if source_switchStackId in source_stack_map:
                        kwargs["switchStackId"] = source_stack_map[source_switchStackId]
                        event_handler("debug", f"Mapping source stack: {source_switchStackId} = {kwargs['switchStackId']}")
                    else:
                        event_handler("error", f"Mapping for source stack {source_switchStackId} not found")
                        continue
                    path = "/networks/{networkId}/switch/stacks/{switchStackId}/" + stack_match.group(2)
                #
                # Write the data to the path
                #        
                meraki_write_path(path, args.api_key, args.base_url, network_data, **kwargs)
        else:
            event_handler("error", f"Skipping import of network {source_network_data['name']}({source_network_data['id']}) because it is not found in import data.")
    elif args.import_command == "devices":
        for serial in import_data["devices"]:
            if args.serials != None and serial not in args.serials:
                event_handler("debug", f"Skipping {serial}")
                continue
            source_network_paths = import_data["devices"][serial]["paths"]
            for sub_path, device_data in source_network_paths.items():
                path = "/devices/{serial}" + sub_path
                #
                # Write the data to the path
                #
                # Should we remove None values everywhere?
                if "switchProfileId" in device_data and device_data["switchProfileId"] == None:
                    device_data.pop("switchProfileId", None)
                meraki_write_path(path, args.api_key, args.base_url, device_data, serial=serial)

def claim_command(args):
    claim_list = []
    if args.serials:
        claim_list = args.serials
    else:
        if args.input_file:
            import_data = import_file(args.input_file)
            devices = import_data["devices"]
        else:
            event_handler("critical", "Input file must be provided when serials is not provided.")                 
        for serial in devices:
            device_data = devices[serial]["paths"]["/"]
            if args.source_network_id:
                if args.source_network_id == device_data["networkId"]:
                    claim_list.append(serial)
            else:
                claim_list.append(serial)
    #
    # See what devices are already claimed in the network
    #
    
    device_data = meraki_read_path("/networks/{networkId}/devices", args.api_key, args.base_url, networkId=args.target_network_id)
    if device_data:
        existing_serials = [device["serial"] for device in device_data]
    else:
        existing_serials = []

    unclaimed_serials = [serial for serial in claim_list if serial not in existing_serials]
    claim_payload = {
        "serials": unclaimed_serials,
        "addAtomically": True
    }
    event_handler("info", f"Claiming {claim_list} in network {args.target_network_id}")
    meraki_write_path("/networks/{networkId}/devices/claim", args.api_key, args.base_url, claim_payload, networkId=args.target_network_id)

def unclaim_command(args):
    unclaim_list = []
    import_data = {}
    if args.serials:
        unclaim_list = args.serials
    else:
        if args.input_file:
            import_data = import_file(args.input_file)
            devices = import_data["devices"]
        else:
            event_handler("critical", "Input file must be provided when serials is not provided.")     
        for serial in devices:
            device_data = devices[serial]["paths"]["/"]
            if args.source_network_id:
                if args.source_network_id == device_data["networkId"]:
                    unclaim_list.append(serial)
            # else:
            #     unclaim_list.append(serial)

    for serial in unclaim_list:
        if import_data:
            if serial in devices:
                device_data = devices[serial]["paths"]["/"]
                network_id = device_data["networkId"]
            else:
                event_handler("error", f"{serial} not in input file.")
                continue
        else:
            device_data = meraki_read_path("/devices/{serial}", args.api_key, args.base_url, serial=serial)
            if device_data:
                network_id = device_data["networkId"]
            else:
                event_handler("error", f"{serial} not found.")
                continue
        event_handler("info", f"Rebooting {serial}.")
        payload = {}
        meraki_write_path("/devices/{serial}/reboot", args.api_key, args.base_url, payload, serial=serial)
        payload = {
            "serial": serial
        }
        event_handler("info", f"Removing {serial} from network {network_id}")
        meraki_write_path("/networks/{networkId}/devices/remove", args.api_key, args.base_url, payload, networkId=network_id)    

    payload = {
        "serials": unclaim_list
    }
    event_handler("debug", f"Unclaiming {unclaim_list} in org {args.org_id}")
    meraki_write_path("/organizations/{organizationId}/inventory/release", args.api_key, args.base_url, payload, organizationId=args.org_id)

def download_spec_command(args):
    parameters = ['version=3']
    spec = meraki_read_path("/organizations/{organizationId}/openapiSpec", args.api_key, args.base_url, parameters=parameters, organizationId=args.org_id)
    export_file(args.output_file, spec)

def event_handler(severity: str, message: str):
    """
    Handle events by logging messages and determining exit behavior based on severity.

    Args:
        message (str): The message to log.
        severity (str): The severity level of the message ('debug', 'info', 'warning', 'error', 'critical').
    """

    severity = severity.lower()
    
    if severity == 'debug':
        logger.debug(message)
    elif severity == 'info':
        logger.info(message)
    elif severity == 'warning':
        logger.warning(message)
        error_log.append(f"{severity}: {message}")
    elif severity == 'error':
        logger.error(message)
        error_log.append(f"{severity}: {message}")
        if args.exit_on_error:
            if args.trace_on_error:
                traceback.print_stack()
            sys.exit(1)
    elif severity == 'critical':
        error_log.append(f"{severity}: {message}")
        logger.critical(message)
        if args.trace_on_error:
            traceback.print_stack()
        sys.exit(1)
    else:
        logger.error(f"Unknown severity level: {severity}")
        if args.exit_on_error:
            sys.exit(1)

# Define log level colors
LOG_COLORS = {
    logging.DEBUG: "\033[0;37m",  # White
    logging.INFO: "\033[0;36m",   # Cyan
    logging.WARNING: "\033[0;33m",# Yellow
    logging.ERROR: "\033[0;31m",  # Red
    logging.CRITICAL: "\033[1;31m" # Bold Red
}

COLORS = {
    "green": "\033[0;32m",
    "yellow": "\033[0;33m",
    "red": "\033[0;31m",
    "blue": "\033[0;34m",
    "reset": "\033[0m"
}

def color_message(message, color):
    return (f"{COLORS.get(color, COLORS['reset'])}{message}{COLORS['reset']}")

class color_formatter(logging.Formatter):
    def format(self, record):
        log_color = LOG_COLORS.get(record.levelno)
        record.msg = f"{log_color}{record.msg}\033[0m"
        return super().format(record)

def setup_logger(level):
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    formatter = color_formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)

def parse_app_args(arguments=None):
    # Create a top-level parser
    parser = argparse.ArgumentParser(description="Meraki Data Tool")
    parser.add_argument('-b', '--base-url', type=str, default=os.getenv('MERAKI_BASE_URL'), help='The base URL for the API.')
    parser.add_argument('-k', '--api-key', type=str, default=os.getenv('MERAKI_DASHBOARD_API_KEY'), help='The Meraki Organization ID.')
    parser.add_argument('-O', '--org-id', type=str, default=os.getenv('MERAKI_ORG_ID'), help='The organization ID to replace in the paths.')
    parser.add_argument('-c', '--max-concurrent-requests', type=int, default=5, help='The maximum number of concurrent requests allowed.')
    parser.add_argument('--log-level', type=str, default='INFO', choices = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help='Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    parser.add_argument('--exit-on-error', action='store_true', help="Exit on error severity.")
    parser.add_argument('--trace-on-error', action='store_true', help="Print stack trace on error.")
    parser.add_argument('--spec-file', default=OPENAPI_SPEC_FILE, type=str, help='The path of the openapi spec file.')


    # Immediately create a subparser holder for a sub-command.
    # The sub-command's string will be stored in "parsed_arguments.cmd"
    #   of the parsed arguments' namespeace object
    subparsers = parser.add_subparsers(dest='command', help='Main commands')

    #
    # Subparser for `download-spec` command
    #
    parser_download_spec = subparsers.add_parser("download-spec", help='Download OpenAPI Spec')
    parser_download_spec.add_argument('-o', '--output_file', type=str, required=True, help='The path to write the file.')
    parser_download_spec.set_defaults(func=download_spec_command)

    #
    # Subparser for `export` command
    #
    parser_export = subparsers.add_parser("export", help='Export Data to File')
    parser_export.set_defaults(func=export_command)
    parser_export.add_argument('-o', '--output_file', type=str, help='The path to the output JSON file.')
    parser_export.add_argument('--org-id', help='Org ID', default=os.getenv('MERAKI_ORG_ID'), type=str)
    parser_export.add_argument('--networks', nargs='+', help='A list of network IDs to export.')
    parser_export.add_argument('--full-export', help='Export all paths', action='store_true')
    parser_export.add_argument('--base-paths', nargs='+', default=['organizations','networks','devices'], choices=['organizations','networks','devices'], help='API base paths to import.')

    #
    # Subparser for `show` command
    #
    parser_show = subparsers.add_parser('show', help='Show resources')
    parser_show.add_argument('--json', help='Show output in JSON', action='store_true')
    parser_show.set_defaults(func=show_command)
    show_subparsers = parser_show.add_subparsers(dest='show_command', help='Resources to show')

    # Subcommand: `show networks`
    parser_show_networks = show_subparsers.add_parser('networks', help='Show networks')
    parser_show_networks.add_argument('--org-id', help='Org ID', default=os.getenv('MERAKI_ORG_ID'), type=str)
    parser_show_networks.add_argument('--tags', nargs='+', help='Filter by tags')

    # Subcommand: `show organizations`
    parser_show_organizations = show_subparsers.add_parser('organizations', help='Show organizations')

    # Subcommand: `show devices`
    parser_show_devices = show_subparsers.add_parser('devices', help='Show devices')
    parser_show_devices.add_argument('--network', type=str, help='Filter by network ID')
    parser_show_devices.add_argument('--org-id', help='Org ID', default=os.getenv('MERAKI_ORG_ID'), type=str)

    # Subcommand: `show templates`
    parser_show_templates = show_subparsers.add_parser('templates', help='Show templates')
    parser_show_templates.add_argument('--org-id', help='Org ID', default=os.getenv('MERAKI_ORG_ID'), type=str)

    # Subcommand: `show me`
    parser_show_templates = show_subparsers.add_parser('me', help='Show Current User')
    parser_show_templates.add_argument('--org-id', help='Org ID', default=os.getenv('MERAKI_ORG_ID'), type=str)    

    #
    # Subparser for `import` command
    #
    parser_import = subparsers.add_parser("import", help='Import from Export File')
    parser_import.set_defaults(func=import_command)
    import_subparsers = parser_import.add_subparsers(dest='import_command', help='Resources to import')

    # Subcommand: `import organizations`
    parser_import_organizations = import_subparsers.add_parser('organizations', help='Import Organizations')
    # Subcommand: `import networks`
    parser_import_networks = import_subparsers.add_parser('networks', help='Import networks')
    # Subcommand: `import devices`
    parser_import_devices = import_subparsers.add_parser('devices', help='Import devices')
    parser_import_devices.add_argument('--ignore-profile', help='Ignore the profiles', action='store_true')
    parser_import_devices.add_argument('-p', '--product-types', nargs='+', choices=PRODUCT_TYPES, help='The categories to import.')    
    # Subcommand: `import templates`
    parser_import_templates = import_subparsers.add_parser('templates', help='Import Templates')
    parser_import_templates.add_argument('--dry-run', help='Do name make a change', action='store_true')
    parser_import_templates.add_argument('-i', '--input-file', type=str, required=True, help='The path to the output JSON file.')
    parser_import_templates.add_argument('--diff', help='Print Diff', action='store_true')
    parser_import_templates.add_argument('--always-write', help='Ignore diff and always write to api', action='store_true')


    parser_import.add_argument('--source-network-id', help='Source Netork ID', type=str)
    parser_import.add_argument('--source-org-id', help='Source Org ID', type=str)


    #
    # Subparser for `unclaim` command
    #
    parser_unclaim = subparsers.add_parser('unclaim', help='Unclaim Devices')
    parser_unclaim.set_defaults(func=unclaim_command)
    parser_unclaim.add_argument('-i', '--input-file', type=str, help='The path to the output JSON file.')
    parser_unclaim.add_argument('--dry-run', help='Do name make a change', action='store_true')
    parser_unclaim_group = parser_unclaim.add_mutually_exclusive_group()
    parser_unclaim_group.add_argument('--source-network-id', help='Source Netork ID', type=str)
    parser_unclaim_group.add_argument('--serials', nargs='+', help='The serial numbers to import.')
    #
    # Subparser for `claim` command
    #
    parser_claim = subparsers.add_parser("claim", help='Claim Devices')
    parser_unclaim.set_defaults(func=claim_command)
    parser_claim.add_argument('-i', '--input-file', type=str, help='The path to the output JSON file.')
    parser_claim.add_argument('--dry-run', help='Do name make a change', action='store_true')
    parser_claim.add_argument('--target-network-id', required=True, help='Target Netork ID', type=str)
    parser_claim_group = parser_claim.add_mutually_exclusive_group()
    parser_claim_group.add_argument('--source-network-id', help='Source Netork ID', type=str)
    parser_claim_group.add_argument('--serials', nargs='+', help='The serial numbers to import.')   

    return parser.parse_args(arguments)    

async def main(args):
    # Execute the function for the subcommand
    if args.command =='export':
        await export_command(args)
    else:
        if hasattr(args, 'func'):
            args.func(args)
    # else:
    #     parser.print_help()

if __name__ == "__main__":
    suppress_logging = False
    output_log = False
    log_path = os.path.join(os.getcwd(), "log")
    if not os.path.exists(log_path):
        os.makedirs(log_path)

    error_log = []
    args = parse_app_args()
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    setup_logger(log_level)
    logger = logging.getLogger()

    config = import_file(os.path.dirname(os.path.realpath(__file__)) + '/meraki-mdt.yml')
    openapi_spec = import_file(args.spec_file)
    logger.debug(args)

    asyncio.run(main(args))
