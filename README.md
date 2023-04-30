# pySigma-backend-carbonblack

![Tests](https://github.com/7RedViolin/pySigma-backend-carbonblack/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/430d03b407f337c2b20029c356355f8a/raw/7RedViolin-pySigma-backend-carbonblack.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma CarbonBlack Backend

This is the carbonblack backend for pySigma. It provides the package `sigma.backends.carbonblack` with the `CarbonBlackBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.carbonblack`:

* CarbonBlack_pipeline: Uses Carbon Black Enterprise EDR field mappings
* CarbonBlackResponse_pipeline: Uses Carbon Black EDR field mappings

It supports the following output formats:

* default: plain CarbonBlack queries
* json: JSON output to include query and rule metadata

This backend is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)

## Side Notes &  Limitations
- Backend uses Carbon Black syntax
- Pipelines exist for both Carbon Black Enterprise EDR and Carbon Black EDR
- Pipelines support linux, windows, and macos product types
- Pipelines support the following category types for field mappings
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
- Any unsupported fields or categories will throw errors