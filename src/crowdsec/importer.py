# -*- coding: utf-8 -*-
"""CrowdSec external import module."""
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict
from urllib.parse import urljoin

import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .helper import clean_config, verify_checksum, read_cti_dump, delete_folder
from .constants import CTI_API_URL, CTI_URL
from .builder import CrowdSecBuilder
from .client import CrowdSecClient, QuotaExceedException


class CrowdSecImporter:
    def __init__(self):
        self.crowdsec_ent = None
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        self.config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(self.config)
        self.crowdsec_cti_key = clean_config(
            get_config_variable(
                "CROWDSEC_IMPORT_KEY", ["crowdsec_import", "key"], self.config
            )
        )
        self.crowdsec_api_version = clean_config(
            get_config_variable(
                "CROWDSEC_IMPORT_VERSION",
                ["crowdsec_import", "api_version"],
                self.config,
                default="v2",
            )
        )

        self.max_tlp = clean_config(
            get_config_variable(
                "CROWDSEC_IMPORT_MAX_TLP",
                ["crowdsec_import", "max_tlp"],
                self.config,
                default="TLP:AMBER",
            )
        )
        self.create_note = get_config_variable(
            "CROWDSEC_IMPORT_CREATE_NOTE",
            ["crowdsec_import", "create_note"],
            self.config,
            default=True,
        )
        self.create_sighting = get_config_variable(
            "CROWDSEC_IMPORT_CREATE_SIGHTING",
            ["crowdsec_import", "create_sighting"],
            self.config,
            default=True,
        )
        tlp_config = clean_config(
            get_config_variable(
                "CROWDSEC_IMPORT_TLP",
                ["crowdsec_import", "tlp"],
                self.config,
                default="TLP_AMBER",
            )
        )
        self.tlp = getattr(stix2, tlp_config)

        self.interval = get_config_variable(
            "CROWDSEC_IMPORT_INTERVAL",
            ["crowdsec_import", "interval"],
            self.config,
            True,
            2,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.config,
        )
        if self.crowdsec_api_version != "v2":
            raise Exception(
                f"crowdsec api version '{self.crowdsec_api_version}' is not supported "
            )
        else:
            self.api_base_url = f"{CTI_API_URL}{self.crowdsec_api_version}/"
        self.client = CrowdSecClient(
            helper=self.helper,
            url=self.api_base_url,
            api_key=self.crowdsec_cti_key,
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def run(self) -> None:
        self.helper.log_info("CrowdSec external import running ...")
        while True:
            sub_folder = None
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("CrowdSec import has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                        (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    # Initiate the run
                    self.helper.log_info("CrowdSec import connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "CrowdSec import connector run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Retrieve CrowdSec CTI dump json
                        try:
                            # dump: Dict[str, Dict] = self.client.get_crowdsec_dump()
                            dump = {"test": "test"}
                        except QuotaExceedException as ex:
                            raise ex

                        if not dump:
                            return

                        # dump_folder = (
                        #         os.path.dirname(os.path.abspath(__file__)) + "/dump"
                        # )
                        # if not os.path.exists(dump_folder):
                        #     raise FileNotFoundError(
                        #         f"Dump folder {dump_folder} does not exist"
                        #     )
                        # sub_folder = os.path.join(dump_folder, str(timestamp))
                        # if not os.path.exists(sub_folder):
                        #     os.makedirs(sub_folder, mode=0o755, exist_ok=True)
                        #     self.helper.log_debug(
                        #         f"Temporary {sub_folder} folder created"
                        #     )
                        #
                        # smoke_ips = {}
                        # smoke = dump.get("smoke", {})
                        # if smoke:
                        #     url = smoke.get("url")
                        #     checksum = smoke.get("checksum")
                        #     checksum_type = smoke.get("checksum_type")
                        #     smoke_file = os.path.join(sub_folder, "smoke.tar.gz")
                        #     self.helper.log_debug(
                        #         f"Downloading smoke file from {url} ..."
                        #     )
                        #     self.client.download_file(url, smoke_file)
                        #     if not verify_checksum(smoke_file, checksum, checksum_type):
                        #         raise Exception(
                        #             "Checksum verification failed for smoke file"
                        #         )
                        #     self.helper.log_debug(
                        #         f"Checksum OK.  Reading smoke file ..."
                        #     )
                        #     smoke_ips = read_cti_dump(smoke_file)
                        #     self.helper.log_debug(f"Smoke IPs count: {len(smoke_ips)}")
                        #
                        # fire_ips = {}
                        # fire = dump.get("fire", {})
                        # if fire:
                        #     fire_file = os.path.join(sub_folder, "fire.tar.gz")
                        #     url = fire.get("url")
                        #     checksum = fire.get("checksum")
                        #     checksum_type = fire.get("checksum_type")
                        #     self.helper.log_debug(
                        #         f"Downloading fire file from {url} ..."
                        #     )
                        #     self.client.download_file(url, fire_file)
                        #     if not verify_checksum(fire_file, checksum, checksum_type):
                        #         raise Exception(
                        #             "Checksum verification failed for fire file"
                        #         )
                        #     self.helper.log_debug(
                        #         f"Checksum OK.  Reading fire file ..."
                        #     )
                        #     fire_ips = read_cti_dump(fire_file)
                        #     self.helper.log_debug(f"Fire IPs count: {len(fire_ips)}")
                        #
                        # ip_list = {**smoke_ips, **fire_ips}

                        ip_list = {
                            "185.188.249.246": {
                                "ip": "185.188.249.246",
                                "reputation": "malicious",
                                "ip_range": "185.188.249.0/24",
                                "background_noise": "high",
                                "confidence": "high",
                                "background_noise_score": 10,
                                "ip_range_score": 5,
                                "as_name": "Contabo GmbH",
                                "as_num": 51167,
                                "ip_range_24": "185.188.249.0/24",
                                "ip_range_24_reputation": "suspicious",
                                "ip_range_24_score": 3,
                                "location": {
                                    "country": "DE",
                                    "city": "D\u00fcsseldorf",
                                    "latitude": 51.2184,
                                    "longitude": 6.7734,
                                },
                                "reverse_dns": "vmi1496716.contaboserver.net",
                                "behaviors": [
                                    {
                                        "name": "http:scan",
                                        "label": "HTTP Scan",
                                        "description": "IP has been reported for performing actions related to HTTP vulnerability scanning and discovery.",
                                        "references": [],
                                    },
                                    {
                                        "name": "http:exploit",
                                        "label": "HTTP Exploit",
                                        "description": "IP has been reported for attempting to exploit a vulnerability in a web application.",
                                        "references": [],
                                    },
                                    {
                                        "name": "http:crawl",
                                        "label": "HTTP Crawl",
                                        "description": "IP has been reported for performing aggressive crawling of web applications.",
                                        "references": [],
                                    },
                                    {
                                        "name": "http:bruteforce",
                                        "label": "HTTP Bruteforce",
                                        "description": "IP has been reported for performing a HTTP brute force attack (either generic HTTP probing or applicative related brute force).",
                                        "references": [],
                                    },
                                ],
                                "history": {
                                    "first_seen": "2023-10-27T22:15:00+00:00",
                                    "last_seen": "2024-05-22T14:30:00+00:00",
                                    "full_age": 209,
                                    "days_age": 208,
                                },
                                "classifications": {
                                    "false_positives": [],
                                    "classifications": [
                                        {
                                            "name": "community-blocklist",
                                            "label": "CrowdSec Community Blocklist",
                                            "description": "IP belongs to the CrowdSec Community Blocklist",
                                        }
                                    ],
                                },
                                "attack_details": [
                                    {
                                        "name": "crowdsecurity/http-bad-user-agent",
                                        "label": "Bad User Agent",
                                        "description": "Detect usage of bad User Agent",
                                        "references": [],
                                    },
                                    {
                                        "name": "crowdsecurity/http-probing",
                                        "label": "HTTP Probing",
                                        "description": "Detect site scanning/probing from a single ip",
                                        "references": [],
                                    },
                                    {
                                        "name": "crowdsecurity/http-crawl-non_statics",
                                        "label": "Aggressive Crawl",
                                        "description": "Detect aggressive crawl on non static resources",
                                        "references": [],
                                    },
                                    {
                                        "name": "crowdsecurity/http-admin-interface-probing",
                                        "label": "HTTP Admin Interface Probing",
                                        "description": "Detect generic HTTP admin interface probing",
                                        "references": [],
                                    },
                                ],
                                "target_countries": {
                                    "US": 25,
                                    "DE": 25,
                                    "FR": 15,
                                    "JP": 7,
                                    "NL": 5,
                                    "GB": 5,
                                    "SG": 4,
                                    "PL": 3,
                                    "RU": 3,
                                    "CA": 2,
                                },
                                "mitre_techniques": [
                                    {
                                        "name": "T1595",
                                        "label": "Active Scanning",
                                        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
                                        "references": [],
                                    },
                                    {
                                        "name": "T1589",
                                        "label": "Gather Victim Identity Information",
                                        "description": "Adversaries may gather information about the victims identity that can be used during targeting.",
                                        "references": [],
                                    },
                                    {
                                        "name": "T1110",
                                        "label": "Brute Force",
                                        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                                        "references": [],
                                    },
                                ],
                                "cves": [],
                                "scores": {
                                    "overall": {
                                        "aggressiveness": 5,
                                        "threat": 2,
                                        "trust": 5,
                                        "anomaly": 0,
                                        "total": 4,
                                    },
                                    "last_day": {
                                        "aggressiveness": 5,
                                        "threat": 2,
                                        "trust": 2,
                                        "anomaly": 0,
                                        "total": 3,
                                    },
                                    "last_week": {
                                        "aggressiveness": 5,
                                        "threat": 2,
                                        "trust": 5,
                                        "anomaly": 0,
                                        "total": 4,
                                    },
                                    "last_month": {
                                        "aggressiveness": 5,
                                        "threat": 2,
                                        "trust": 5,
                                        "anomaly": 0,
                                        "total": 4,
                                    },
                                },
                                "state": "validated",
                                "expiration": "2024-05-29T14:31:40.935000",
                                "references": [],
                            }
                        }

                        self.helper.log_debug(f"Total IPs list count: {len(ip_list)}")
                        self.helper.log_info("Query CrowdSec API Dump - Completed")
                        delete_folder(sub_folder)
                        self.helper.log_debug("Temporary folder deleted")
                        # Preparing the bundle to be sent to OpenCTI worker
                        bundle_objects = []
                        # Creating the bundle from the list

                        for ip, ip_data in ip_list.items():
                            indicator = None
                            builder = CrowdSecBuilder(
                                self.helper, self.config, cti_data=ip_data
                            )
                            cti_external_reference = {
                                "source_name": "CrowdSec CTI",
                                "url": urljoin(CTI_URL, ip),
                                "description": "CrowdSec CTI url for this IP",
                            }

                            stix_observable = builder.add_observable_ipv4_address(
                                ip,
                                markings=[self.tlp],
                                external_references=[cti_external_reference],
                            )
                            # Add note
                            if self.create_note:
                                builder.add_note(
                                    observable_id=stix_observable.id,
                                    markings=[self.tlp],
                                )
                                # Create sightings relationship between CrowdSec organisation and observable
                            if self.create_sighting:
                                builder.add_sighting(
                                    observable_id=stix_observable.id,
                                    markings=[self.tlp],
                                    sighting_ext_refs=[cti_external_reference],
                                    indicator=indicator if indicator else None,
                                )

                            bundle_objects.extend(builder.get_bundle())

                        if bundle_objects:
                            bundle = stix2.Bundle(bundle_objects, allow_custom=True)
                            bundle_json = bundle.serialize()
                            # Sending the bundle
                            self.helper.send_stix2_bundle(
                                bundle_json,
                                update=self.update_existing_data,
                                work_id=work_id,
                            )

                        # Store the current timestamp as a last run
                        message = (
                                "CrowdSec import connector successfully run, storing last_run as "
                                + str(timestamp)
                        )
                        self.helper.log_info(message)
                        self.helper.set_state({"last_run": timestamp})
                        self.helper.api.work.to_processed(work_id, message)
                        self.helper.log_info(
                            "Last_run stored, next run in: "
                            + str(round(self.get_interval() / 60 / 60 / 24, 2))
                            + " days"
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))

                    time.sleep(60)
                else:
                    # wait for next run
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                delete_folder(sub_folder)
                self.helper.log_info("CrowdSec import connector stop")
                exit(0)
            except Exception as e:
                delete_folder(sub_folder)
                self.helper.log_error(str(e))
                time.sleep(60)
