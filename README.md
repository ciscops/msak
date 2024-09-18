# Meraki Data Tool

A tool that show, exports, and manipulates data in the Meraki Dashboard API
```
mdt % ./mdt.py --help
usage: mdt.py [-h] [-b BASE_URL] [-k API_KEY] [-O ORG_ID] [-c MAX_CONCURRENT_REQUESTS] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--exit-on-error]
              [--trace-on-error] [--spec-file SPEC_FILE]
              {download-spec,export,show,import,unclaim,claim} ...

Meraki Data Tool

positional arguments:
  {download-spec,export,show,import,unclaim,claim}
                        Main commands
    download-spec       Download OpenAPI Spec
    export              Export Data to File
    show                Show resources
    import              Import from Export File
    unclaim             Unclaim Devices
    claim               Claim Devices
```

## Show

Show Current Credentials:
```
(venv-mdt)% ./mdt.py show me
INFO: Reading /Users/stevenca/Workspace/mdt/mdt.yaml...
INFO: Reading meraki-openapi-spec.json...
Name:            Steven Carter
Email:           stevenca@cisco.com
MERAKI_ORG_ID:   XXXXXXXXXXXXXXXXXXX (Org X)
MERAKI_BASE_URL: https://api.gov-meraki.com/api/v1
```

Show Organiztions:
```
(venv-mdt)% ./mdt.py show organizations
id                   name                             
XXXXXXXXXXXXXXXXXXX  Org X
YYYYYYYYYYYYYYYYYYY  Org Y      
ZZZZZZZZZZZZZZZZZZZ  Org Z                       
```

Show Networks:
```
(venv-mdt)% ./mdt.py show networks       

id                    name                 productTypes                                                                                      timeZone             tags                                                 
L_AAAAAAAAAAAAAAAAAA  Network A              ['appliance', 'camera', 'cellularGateway', 'switch']                                              America/New_York     ['discover-clients']                                 
L_BBBBBBBBBBBBBBBBBB  Network B          ['appliance']                                                                                     US/Eastern  
```


## Export

Export entire Organization:
```
(venv-mdt)% ./mdt.py export
```

Export specfic network and the assocated templates:
```
(venv-mdt)% ./mdt.py export --networks NetworkA NetworkB NetworkC -o <output file>.json
```

## Import

Import Templates:
```
(venv-mdt)% ./mdt.py import templates -i <export file>.json
```

Import Networks:
```
(venv-mdt)% ./mdt.py import networks --networks NetworkB -i <export file>.json --diff
```

Import Devices:
```
(venv-mdt)% ./mdt.py import devices -i <export file>.json --source-networks NetworkB --diff
```

## Unclaim

Unclaim devices by serial number
```
(venv-mdt)% ./mdt.py unclaim --serials AAAA-BBBB-CCCC DDDD-EEEE-FFFF-GGGG
```

Unclaim all devices in an export file from a specific network:
```
(venv-mdt)% ./mdt.py unclaim -i <export file>.json --source-network-ids NetworkC
```

Unclaim all devices in current org for specific network name:
```
(venv-mdt)% ./mdt.py unclaim --networks NetworkA NetworkB
```

## Claim

Claim all devices in an export file into
the current organization into network of the same name.
```
(venv-mdt)% ./mdt.py claim -i <export file>.json --network NetworkA
```

## TODO
- Symantic Versioning

