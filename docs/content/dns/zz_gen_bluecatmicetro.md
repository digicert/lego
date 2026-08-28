---
title: "BlueCat Micetro"
date: 2019-03-03T16:39:46+01:00
draft: false
slug: bluecatmicetro
dnsprovider:
  since:    "v4.31.0"
  code:     "bluecatmicetro"
  url:      "https://bluecatnetworks.com/integrations/micetro/"
---

<!-- THIS DOCUMENTATION IS AUTO-GENERATED. PLEASE DO NOT EDIT. -->
<!-- providers/dns/bluecatmicetro/bluecatmicetro.toml -->
<!-- THIS DOCUMENTATION IS AUTO-GENERATED. PLEASE DO NOT EDIT. -->


Configuration for [BlueCat Micetro](https://bluecatnetworks.com/integrations/micetro/).


<!--more-->

- Code: `bluecatmicetro`
- Since: v4.31.0


Here is an example bash command using the BlueCat Micetro provider:

```bash
BLUECAT_MICETRO_ENDPOINT="https://micetro.example.com/mmws/api/v2" \
BLUECAT_MICETRO_USERNAME="xxx" \
BLUECAT_MICETRO_PASSWORD="yyy" \
lego run --dns bluecatmicetro -d '*.example.com' -d example.com
```




## Credentials

| Environment Variable Name | Description |
|-----------------------|-------------|
| `BLUECAT_MICETRO_ENDPOINT` | The Micetro Web Services API base URL, including scheme, host, and API path (e.g. https://micetro.example.com/mmws/api/v2) |
| `BLUECAT_MICETRO_PASSWORD` | API password |
| `BLUECAT_MICETRO_USERNAME` | API username |

The environment variable names can be suffixed by `_FILE` to reference a file instead of a value.
More information [here]({{% ref "dns#configuration-and-credentials" %}}).


## Additional Configuration

| Environment Variable Name | Description |
|--------------------------------|-------------|
| `BLUECAT_MICETRO_TTL` | The TTL of the TXT record used for the DNS challenge in seconds (Default: 10) |

The environment variable names can be suffixed by `_FILE` to reference a file instead of a value.
More information [here]({{% ref "dns#configuration-and-credentials" %}}).





<!-- THIS DOCUMENTATION IS AUTO-GENERATED. PLEASE DO NOT EDIT. -->
<!-- providers/dns/bluecatmicetro/bluecatmicetro.toml -->
<!-- THIS DOCUMENTATION IS AUTO-GENERATED. PLEASE DO NOT EDIT. -->
