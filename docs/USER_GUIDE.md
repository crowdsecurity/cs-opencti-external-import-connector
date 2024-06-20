![CrowdSec Logo](images/logo_crowdsec.png)

# OpenCTI CrowdSec internal enrichment connector

## User Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Description](#description)
  - [Configuration](#configuration)
    - [Parameters meaning](#parameters-meaning)
  - [Quotas](#quotas)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description

The connector uses the CrowdSec API to collect IPs from a partial dump of CrowdSec CTI.
The number of IPs you will get in the dump will depend on your subscription.

For each IP, an `Ipv4-Addr` or `IPv6-Addr` observable is created (or updated) and enriched. Enrichment depends on the configurations below. 

### Configuration

Configuration parameters are provided using environment variables as described below. Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.



#### Parameters meaning

| Docker environment variable                   | Mandatory | Type | Description                                                                                                                                                                                                                                         |
|-----------------------------------------------| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPENCTI_URL`                                 | Yes  | String    | The URL of the OpenCTI platform.                                                                                                                                                                                                                    |
| `OPENCTI_TOKEN`                               | Yes          | String  | The default admin token configured in the OpenCTI platform parameters file.                                                                                                                                                                         |
| `CONNECTOR_ID`                                | Yes          | String    | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                                                                                  |
| `CONNECTOR_NAME`                              | Yes          | String    | Name of the CrowdSec import connector to be shown in OpenCTI.                                                                                                                                                                                       |
| `CONNECTOR_SCOPE`                             | Yes          | String    | Supported scopes: `IPv4-Addr`, `IPv6-Addr`                                                                                                                                                                                                          |
| `CONNECTOR_CONFIDENCE_LEVEL`                  | Yes          | Integer | The default confidence level  (an integer between 0 and 100).                                                                                                                                                                                       |
| `CONNECTOR_UPDATE_EXISTING_DATA`              | No | Boolean | Enable/disable update of existing data in database. <br />Default: `false`                                                                                                                                                                          |
| `CONNECTOR_LOG_LEVEL`                         | No         | String    | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). <br />Default: `info`                                                                                                                                 |
| `CROWDSEC_KEY`                                | Yes       | String | CrowdSec CTI  API key. See [instructions to obtain it](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)                                                                                                             |
| `CROWDSEC_API_VERSION`                        | No | String | CrowdSec API version. Supported version: `v2`. <br />Default: `v2`.                                                                                                                                                                                 |
| `CROWDSEC_DUMP_LISTS` | No | String | List of dump types separated by comma. <br />- `fire`: contains the IPs part of the CrowdSec community blocklist. The number of IPs included  is not fixed and can vary over time.<br />- `smoke`:   This dump contains most of the IPs reported by the CrowdSec community. This dump includes a fixed number of IPs according to your subscription. We propose a dump of the smoke database for the top 250K, 500K, 1M or a custom amount of IPs.<br />Default:  `'fire'`.<br /> |
| `CROWDSEC_IMPORT_INTERVAL` | No | Number | Interval in hours between two imports.<br />Default: `24` |
| `CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT` | No | Number | Maximum number of IP addresses to enrich in one import.<br />Default: `10000` |
| `CROWDSEC_MAX_TLP`                            | No     | String | Do not send any data to CrowdSec if the TLP of the observable is greater than `crowdsec_max_tlp`. <br />Default: `TLP:AMBER`                                                                                                                        |
| `CROWDSEC_TLP` | No | String | TLP for created observable. Possible values are: `TLP_WHITE`, `TLP_GREEN`, `TLP_AMBER`, `TLP_RED` . If not set (`None` value), observable will be created without TLP. If an observable already exists, its TLP will be left unchanged.<br />Default: `None` |
| `CROWDSEC_LABELS_SCENARIO_NAME`               | No | Boolean | Enable/disable labels creation based on CTI scenario's name.<br />Default: `true`                                                                                                                                                                  |
| `CROWDSEC_LABELS_SCENARIO_LABEL`              | No | Boolean | Enable/disable labels creation based on CTI scenario's label.<br />Default: `false`                                                                                                                                                      |
| `CROWDSEC_LABELS_SCENARIO_COLOR`              | No | String | Color of scenario based labels.<br />Default: `#2E2A14` ![](./images/labels/2E2A14.png)                                                                                                                                                            |
| `CROWDSEC_LABELS_CVE`                         | No | Boolean | Enable/Disable CTI cve name based labels.<br />Default: `true`                                                                                                                                                                                 |
| `CROWDSEC_LABELS_CVE_COLOR`                   | No | String | Color of cve based labels.<br />Default: `#800080` ![](./images/labels/800080.png)                                                                                                                                                                 |
| `CROWDSEC_LABELS_MITRE`                       | No | Boolean | Enable/Disable CTI mitre technique based labels.<br />Default: `true`                                                                                                                                                                          |
| `CROWDSEC_LABELS_MITRE_COLOR`                 | No | String | Color of mitre technique based labels.<br />Default: `#000080` ![](./images/labels/000080.png)                                                                                                                                                     |
| `CROWDSEC_LABELS_BEHAVIOR`                    | No | Boolean | Enable/Disable CTI behavior based labels.<br />Default: `false`                                                                                                                                                                                    |
| `CROWDSEC_LABELS_BEHAVIOR_COLOR`              | No | String | Color of behavior based labels.<br />Default: `#808000` ![](./images/labels/808000.png)                                                                                                                                                            |
| `CROWDSEC_LABELS_REPUTATION`                  | No | Boolean | Enable/Disable CTI reputation based labels.<br />Default: `true`                                                                                                                                                                               |
| `CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR`  | No | String | Color of malicious reputation label. <br />Default: `#FF0000` ![](./images/labels/FF0000.png)                                                                                                                                                       |
| `CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR` | No | String | Color of suspicious reputation label. <br />Default: `#FFA500` ![](./images/labels/FFA500.png)                                                                                                                                                      |
| `CROWDSEC_LABELS_REPUTATION_SAFE_COLOR`       | No | String | Color of safe reputation label. <br />Default: `#00BFFF` ![](./images/labels/00BFFF.png)                                                                                                                                                            |
| `CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR`      | No | String | Color of safe reputation label. <br />Default: `#808080` ![](./images/labels/808080.png)                                                                                                                                                            |
| `CROWDSEC_INDICATOR_CREATE_FROM`              | No | String | List of reputations to create indicators from (malicious, suspicious, known, safe) separated by comma. <br />Default: empty `'malicious,suspicious,known'`.<br />If an IP is detected with a reputation that belongs to this list, an indicator based on the observable will be created. |
| `CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE`   | No | Boolean | Create attack patterns from MITRE techniques <br />If an indicator has been created, there will be a `targets` relationship between the attack pattern and the indicator. Otherwise, there will be a `related-to` relationship between the attack pattern and the observable <br />There will be a `targets` relationship between the attack pattern and a location created from targeted country.<br />Default `true` |
| `CROWDSEC_VULNERABILITY_CREATE_FROM_CVE` | No | Boolean | Create vulnerability from CVE.<br />There will  be a `related-to` relationship between the vulnerabilty and the observable<br />Default `true` |
| `CROWDSEC_CREATE_NOTE`                        | No | Boolean | Enable/disable creation of a note in observable for each enrichment.<br />Default: `true`                                                                                                                                                      |
| `CROWDSEC_CREATE_SIGHTING`                    | No | Boolean | Enable/disable creation of a sighting of observable related to CrowdSec organization.<br />Default: `true`                                                                                                                                         |
| `CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION` | No | Boolean | Enable/disable saving the last CrowdSec enrichment date in observable description.<br />Default: `true` |
| `CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS` | No | Number | Minimum delay (in seconds) between two CrowdSec enrichments.<br />Default: `86400` <br />Use it to avoid too frequent calls to CrowdSec's CTI API.<br />Requires the last CrowdSec enrichment to be saved in the description, as we'll be comparing this date with the current one.<br />if you are also using the [CrowdSec Internal Enrichment connector](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector), please ensure to also set `CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION=true` and a sufficiently high value of `CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS` in the internal enrichment connector. |
| `CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS` | No | Boolean | Enable/Disable creation of a sighting of observable related to a targeted country<br />Default: `false`<br />Sighting count represents the percentage distribution of the targeted country among all the countries targeted by the attacker. |

You could also use the `config.yml`file of the connector to set the variable.  

In this case, please put the variable name in lower case and separate it into 2 parts using the first underscore `_`. For example, the docker setting `CROWDSEC_MAX_TLP=TLP:AMBER` becomes : 

```yaml
crowdsec:
    max_tlp: 'TLP:AMBER'
```

You will find a `config.yml.sample` file as example.



### Quotas

An API key is limited to 24 queries per day. This should be taken into account when setting the import job frequency (see above  `CROWDSEC_IMPORT_INTERVAL` configuration ).
