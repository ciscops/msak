# Meraki Swiss Army Knife

A tool that shows, imports/exports, and manipulates data in the Meraki Dashboard API

**WARNING: This is sample code.  This code is for you to use as you may; however, there is no support for this code.**

**No refunds!  No returns!**

## Installation

```
python3 -venv venv-msak
. ./venv-msak/bin/activate
pip3 install -r requirements
```

## Environment Variable

MSAK requires information to work.  In particular, the following should be set:

* Meraki API Base URL: Set either by specifying `--base-url` or setting the environment variable `MERAKI_DASHBOARD_API_KEY`
* Meraki Dashboard API Key: Set either by specifying `--api-key` or setting the environment variable `MERAKI_BASE_URL`
* Meraki Organization ID: Set either by specifying `--org-id` or setting the environment variable `MERAKI_ORG_ID`


## Usage
```
% ./msak --help
usage: msak [-h] [-b BASE_URL] [-k API_KEY] [-O ORG_ID] [-c MAX_CONCURRENT_REQUESTS] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--exit-on-error] [--trace-on-error]
            [--spec-file SPEC_FILE]
            {download-spec,export,import,show,create,unclaim,release,claim} ...

Meraki Data Tool

positional arguments:
  {download-spec,export,import,show,create,unclaim,release,claim}
                        Main commands
    download-spec       Download OpenAPI Spec
    export              Export Data to File
    import              Import from Export File
    show                Show resources
    create              Create Resources
    unclaim             Unclaim Devices
    release             Release Devices
    claim               Claim Devices

options:
  -h, --help            show this help message and exit
  -b BASE_URL, --base-url BASE_URL
                        The base URL for the API.
  -k API_KEY, --api-key API_KEY
                        The Meraki Organization ID.
  -O ORG_ID, --org-id ORG_ID
                        The organization ID to replace in the paths.
  -c MAX_CONCURRENT_REQUESTS, --max-concurrent-requests MAX_CONCURRENT_REQUESTS
                        The maximum number of concurrent requests allowed.
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  --exit-on-error       Exit on error severity.
  --trace-on-error      Print stack trace on error.
  --spec-file SPEC_FILE
                        The path of the openapi spec file.
```

## Common Operations

### Show

Show Current Credentials:
```
(venv-mdt)% ./msak show me
INFO: Reading /Users/stevenca/Workspace/mdt/mdt.yaml...
INFO: Reading meraki-openapi-spec.json...
Name:            Steven Carter
Email:           stevenca@cisco.com
MERAKI_ORG_ID:   XXXXXXXXXXXXXXXXXXX (Org X)
MERAKI_BASE_URL: https://api.gov-meraki.com/api/v1
```

Show Organiztions:
```
(venv-mdt)% ./msak show organizations
id                   name                             
XXXXXXXXXXXXXXXXXXX  Org X
YYYYYYYYYYYYYYYYYYY  Org Y      
ZZZZZZZZZZZZZZZZZZZ  Org Z                       
```

Show Networks:
```
(venv-mdt)% ./msak show networks       

id                    name                 productTypes                                                                                      timeZone             tags                                                 
L_AAAAAAAAAAAAAAAAAA  Network A              ['appliance', 'camera', 'cellularGateway', 'switch']                                              America/New_York     ['discover-clients']                                 
L_BBBBBBBBBBBBBBBBBB  Network B          ['appliance']                                                                                     US/Eastern  
```


### Export

Export entire Organization:
```
(venv-mdt)% ./msak export
```

Export specfic network and the assocated templates:
```
(venv-mdt)% ./msak export --networks NetworkA NetworkB NetworkC -o <output file>.json
```

### Import

Import Templates:
```
(venv-mdt)% ./msak import templates -i <export file>.json
```

Import Networks:
```
(venv-mdt)% ./msak import networks --networks NetworkB -i <export file>.json --diff
```

Import Devices:
```
(venv-mdt)% ./msak import devices -i <export file>.json --source-networks NetworkB --diff
```

### Unclaim

Unclaim devices by serial number
```
(venv-mdt)% ./msak unclaim --serials AAAA-BBBB-CCCC DDDD-EEEE-FFFF-GGGG
```

Unclaim all devices in an export file from a specific network:
```
(venv-mdt)% ./msak unclaim -i <export file>.json --source-network-ids NetworkC
```

Unclaim all devices in current org for specific network name:
```
(venv-mdt)% ./msak unclaim --networks NetworkA NetworkB
```

### Claim

Claim all devices in an export file into
the current organization into network of the same name.
```
(venv-mdt)% ./msak claim -i <export file>.json --network NetworkA
```

## TODO
- Symantic Versioning

