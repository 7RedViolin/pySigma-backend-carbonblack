# pySigma-backend-carbonblack

![Tests](https://github.com/7RedViolin/pySigma-backend-carbonblack/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/430d03b407f337c2b20029c356355f8a/raw/7RedViolin-pySigma-backend-carbonblack.json)
![Status](https://img.shields.io/badge/Status-stable-green)

# pySigma CarbonBlack Backend

This is the carbonblack backend for pySigma. It provides the package `sigma.backends.carbonblack` with the `CarbonBlackBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.carbonblack`:

* CarbonBlack_pipeline: Uses Carbon Black Enterprise EDR process-level field mappings
* CarbonBlackEvents_pipeline: Uses Carbon Black Enterprise EDR event-level field mappings
* CarbonBlackResponse_pipeline: Uses Carbon Black EDR process_level field mappings

It supports the following output formats:

* default: plain CarbonBlack queries
* json: JSON output to include query and rule metadata

This backend is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)
* [RCEMaddox](https://github.com/RCEMaddox)

## Installation
This can be installed via pip from PyPI

```bash
pip install pysigma-backend-carbonblack
```

## Usage

### pySigma
```python
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.pipelines.carbonblack import CarbonBlack_pipeline, CarbonBlackResponse_pipeline
import yaml

from sigma.rule import SigmaRule

rule = SigmaRule.from_yaml("""
title: Invoke-Mimikatz CommandLine
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: Invoke-Mimikatz
    condition: sel""")

cb_backend = CarbonBlackBackend(CarbonBlack_pipeline())

# If you want to use the field names for the legacy Carbon Black EDR (fka Response)
# cbr_backend = CarbonBlackBackend(CarbonBlackResponse_pipeline())

print(f"Cb query: {cb_backend.convert_rule(rule)[0]}")

#print(f"CbR query: {cbr_backend.convert_rule(rule)[0]}")
```

## Side Notes &  Limitations
- Backend uses Carbon Black syntax
- Pipelines exist for both Carbon Black Enterprise EDR and Carbon Black EDR
- Both pipelines support linux, windows, and macos product types
- Both pipelines support the following category types for field mappings
  - `process_creation`
  - `file_event`
  - `file_change`
  - `file_rename`
  - `file_delete`
  - `image_load`
  - `registry_add`
  - `registry_delete`
  - `registry_event`
  - `registry_set`
  - `network_connection`
  - `firewall`
- Below is a chart of supported fields. Any unsupported fields or categories will throw errors

| Field Name | Carbon Black Response | Carbon Black Cloud | Carbon Black Cloud Events |
| --- | --- | --- | --- |
| CommandLine | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Company | :heavy_check_mark: | :heavy_check_mark: | :x: |
| CurrentDirectory | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Description | :heavy_check_mark: | :heavy_check_mark: | :x: |
| DestinationHostname | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| DestinationIp | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| DestinationPort | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| DstPort | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Image | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| ImageLoaded | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| ImagePath | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| IntegrityLevel | :x: | :heavy_check_mark: | :x: |
| OriginalFileName | :x: | :heavy_check_mark: | :x: |
| ParentCommandLine | :x: | :heavy_check_mark: | :x: |
| ParentImage | :heavy_check_mark: | :heavy_check_mark: | :x: |
| ParentProcessId | :heavy_check_mark: | :heavy_check_mark: | :x: |
| ProcessId | :heavy_check_mark: | :heavy_check_mark: | :x: |
| Product | :heavy_check_mark: | :heavy_check_mark: | :x: |
| Protocol | :x: | :heavy_check_mark: | :heavy_check_mark: |
| SourceIp | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| SourcePort | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| SrcPort | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| TargetFilename | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| TargetObject | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| User | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| dst_ip | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| dst_port | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| md5 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| sha256 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| src_ip | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| src_port | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |