# -*- coding: utf-8 -*-
"""CrowdSec external import module."""
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict
from urllib.parse import urljoin

import stix2
import yaml
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from stix2 import Identity

from .builder import CrowdSecBuilder
from .client import CrowdSecClient, QuotaExceedException
from .constants import CTI_API_URL, CTI_URL
from .helper import (
    clean_config,
    delete_folder,
    handle_observable_description,
    verify_checksum,
    read_cti_dump,
)


class CrowdSecImporter:
    BATCH_SIZE = 100

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

        self.crowdsec_ent_name = "CrowdSec"
        self.crowdsec_ent_desc = "Curated Threat Intelligence Powered by the Crowd"

        self.crowdsec_cti_key = clean_config(
            get_config_variable("CROWDSEC_KEY", ["crowdsec", "key"], self.config)
        )
        self.crowdsec_api_version = clean_config(
            get_config_variable(
                "CROWDSEC_API_VERSION",
                ["crowdsec", "api_version"],
                self.config,
                default="v2",
            )
        )

        self.max_tlp = clean_config(
            get_config_variable(
                "CROWDSEC_MAX_TLP",
                ["crowdsec", "max_tlp"],
                self.config,
                default="TLP:AMBER",
            )
        )
        self.create_note = get_config_variable(
            "CROWDSEC_CREATE_NOTE",
            ["crowdsec", "create_note"],
            self.config,
            default=True,
        )
        self.create_sighting = get_config_variable(
            "CROWDSEC_CREATE_SIGHTING",
            ["crowdsec", "create_sighting"],
            self.config,
            default=True,
        )
        tlp_config = clean_config(
            get_config_variable(
                "CROWDSEC_TLP",
                ["crowdsec", "tlp"],
                self.config,
                default=None,
            )
        )
        self.tlp = getattr(stix2, tlp_config) if tlp_config else None

        self.min_delay_between_enrichments = get_config_variable(
            "CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS",
            ["crowdsec", "min_delay_between_enrichments"],
            self.config,
            default=300,
            isNumber=True,
        )

        self.last_enrichment_date_in_description = get_config_variable(
            "CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION",
            ["crowdsec", "last_enrichment_date_in_description"],
            self.config,
            default=True,
        )

        self.create_targeted_countries_sigthings = get_config_variable(
            "CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS",
            ["crowdsec", "create_targeted_countries_sightings"],
            self.config,
            default=False,
        )

        raw_indicator_create_from = clean_config(
            get_config_variable(
                "CROWDSEC_INDICATOR_CREATE_FROM",
                ["crowdsec", "indicator_create_from"],
                self.config,
                default="malicious,suspicious,known",
            )
        )

        self.indicator_create_from = raw_indicator_create_from.split(",")

        raw_dump_lists = clean_config(
            get_config_variable(
                "CROWDSEC_DUMP_LISTS",
                ["crowdsec", "dump_lists"],
                self.config,
                default="fire",
            )
        )

        self.dump_lists = raw_dump_lists.split(",")

        self.attack_pattern_create_from_mitre = get_config_variable(
            "CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE",
            ["crowdsec", "attack_pattern_create_from_mitre"],
            self.config,
            default=True,
        )

        self.interval = get_config_variable(
            "CROWDSEC_IMPORT_INTERVAL",
            ["crowdsec", "import_interval"],
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
                f"CrowdSec api version '{self.crowdsec_api_version}' is not supported "
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

    @staticmethod
    def format_duration(seconds: int) -> str:
        return str(timedelta(seconds=seconds))

    def get_or_create_crowdsec_ent(self) -> Identity:
        if getattr(self, "crowdsec_ent", None) is not None:
            return self.crowdsec_ent
        crowdsec_ent = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.crowdsec_ent_name
        )
        if not crowdsec_ent:
            self.crowdsec_ent = self.helper.api.identity.create(
                type="Organization",
                name=self.crowdsec_ent_name,
                description=self.crowdsec_ent_desc,
            )
        else:
            self.crowdsec_ent = crowdsec_ent
        return self.crowdsec_ent

    def run(self) -> None:
        self.helper.log_info("CrowdSec external import running ...")
        while True:
            sub_folder = None
            try:
                # Get the current timestamp and check
                run_start_timestamp = int(time.time())
                current_state = self.helper.get_state() or {}

                now = datetime.utcnow().replace(microsecond=0)
                last_run = current_state.get("last_run", 0)
                last_run = datetime.utcfromtimestamp(last_run).replace(microsecond=0)

                if last_run.year == 1970:
                    self.helper.log_info("CrowdSec import has never run")
                else:
                    self.helper.log_info(f"Connector last run: {last_run}")

                # If the last_run is old enough, run the connector
                if (now - last_run).total_seconds() > self.get_interval():
                    # Initiate the run
                    self.helper.log_info("CrowdSec import connector will run!")
                    friendly_name = f"CrowdSec import connector run @ {now}"
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Retrieve CrowdSec CTI dump json
                        try:
                            self.helper.log_info("Query CrowdSec API Dump - Started")
                            dump: Dict[str, Dict] = self.client.get_crowdsec_dump()
                            self.helper.log_info("Query CrowdSec API Dump - Completed")
                        except QuotaExceedException as ex:
                            raise ex

                        if not dump:
                            return

                        dump_folder = (
                            os.path.dirname(os.path.abspath(__file__)) + "/dump"
                        )
                        if not os.path.exists(dump_folder):
                            raise FileNotFoundError(
                                f"Dump folder {dump_folder} does not exist"
                            )
                        sub_folder = os.path.join(dump_folder, str(run_start_timestamp))
                        if not os.path.exists(sub_folder):
                            os.makedirs(sub_folder, mode=0o755, exist_ok=True)
                            self.helper.log_debug(
                                f"Temporary {sub_folder} folder created"
                            )

                        ip_list = {}
                        for dump_list in self.dump_lists:
                            dump_file = os.path.join(sub_folder, f"{dump_list}.tar.gz")
                            list_info = dump.get(dump_list, {})
                            url = list_info.get("url", "")
                            checksum = list_info.get("checksum")
                            checksum_type = list_info.get("checksum_type")
                            if url:
                                self.helper.log_debug(
                                    f"Downloading {dump_list} file from {url} ..."
                                )
                                self.client.download_file(url, dump_file)
                                if not verify_checksum(
                                    dump_file, checksum, checksum_type
                                ):
                                    raise Exception(
                                        f"Checksum verification failed for {dump_list} file"
                                    )
                                self.helper.log_debug(
                                    f"Checksum OK.  Reading {dump_list} file ..."
                                )
                                dump_ips = read_cti_dump(dump_file)
                                self.helper.log_debug(
                                    f"{dump_list} IPs count: {len(dump_ips)}"
                                )
                                ip_list = {**ip_list, **dump_ips}
                            else:
                                self.helper.log_debug(f"No URL found for {dump_list}")

                        ip_count = len(ip_list)
                        self.helper.log_info(f"Total IPs count: {ip_count}")

                        delete_folder(sub_folder)
                        self.helper.log_debug("Temporary folder deleted")
                        self.helper.log_info(
                            "Files have been successfully parsed. Sending to OpenCTI starts."
                        )

                        counter = 0
                        ip_items = list(ip_list.items())
                        total_batch_count = (
                            ip_count + self.BATCH_SIZE - 1
                        ) // self.BATCH_SIZE
                        start_enrichment_time = time.time()
                        # Initialize seen labels to avoid duplicates label creation
                        seen_labels = set()
                        for i in range(0, ip_count, self.BATCH_SIZE):
                            batch = ip_items[i : i + self.BATCH_SIZE]
                            batch_start_time = time.time()
                            batch_index = i // self.BATCH_SIZE + 1
                            self.helper.log_info(
                                f"Processing batch {batch_index}/{total_batch_count} with {len(batch)} IPs"
                            )
                            # Preparing the bundle to be sent to OpenCTI worker
                            batch_bundle_objects = []
                            batch_labels = []
                            for ip, cti_data in batch:
                                start_time = time.time()
                                counter += 1
                                self.helper.log_debug(
                                    f"Processing IP {counter}/{ip_count}: {ip}"
                                )
                                # Preparing the bundle to be sent to OpenCTI worker
                                bundle_objects = []
                                # Get the current timestamp for each IP processed
                                ip_timestamp = int(start_time)
                                # Early return if last enrichment was less than some configured time
                                database_observable = (
                                    self.helper.api.stix_cyber_observable.read(
                                        filters={
                                            "mode": "and",
                                            "filters": [
                                                {
                                                    "key": "value",
                                                    "values": [ip],
                                                }
                                            ],
                                            "filterGroups": [],
                                        }
                                    )
                                )
                                handle_description = handle_observable_description(
                                    ip_timestamp, database_observable
                                )
                                time_since_last_enrichment = handle_description[
                                    "time_since_last_enrichment"
                                ]
                                min_delay = self.min_delay_between_enrichments
                                if (
                                    time_since_last_enrichment != -1
                                    and time_since_last_enrichment < min_delay
                                ):
                                    message = (
                                        f"Last enrichment was less than {min_delay} seconds ago, "
                                        f"skipping enrichment for IP: {ip}"
                                    )
                                    self.helper.log_debug(message)
                                    # Skipping the enrichment for this IP
                                    continue

                                description = None
                                if self.last_enrichment_date_in_description:
                                    description = handle_description["description"]

                                # Retrieve specific data from CTI
                                self.helper.log_debug(f"CTI data for {ip}: {cti_data}")
                                reputation = cti_data.get("reputation", "")
                                mitre_techniques = cti_data.get("mitre_techniques", [])
                                cves = cti_data.get("cves", [])

                                indicator = None
                                builder = CrowdSecBuilder(
                                    self.helper,
                                    self.config,
                                    cti_data=cti_data,
                                    organisation=self.get_or_create_crowdsec_ent(),
                                )
                                cti_external_reference = {
                                    "source_name": "CrowdSec CTI",
                                    "url": urljoin(CTI_URL, ip),
                                    "description": "CrowdSec CTI url for this IP",
                                }

                                labels = builder.handle_labels()
                                for label in labels:
                                    label_tuple = (label["value"], label["color"])
                                    if label_tuple not in seen_labels:
                                        seen_labels.add(label_tuple)
                                        batch_labels.append(label)

                                stix_observable = (
                                    builder.upsert_observable_ipv4_address(
                                        description=description,
                                        labels=labels,
                                        markings=[self.tlp] if self.tlp else None,
                                        external_references=[cti_external_reference],
                                        update=True if database_observable else False,
                                    )
                                )
                                self.helper.log_debug(
                                    f"STIX Observable created/updated: {stix_observable}"
                                )
                                # Start Bundle creation wby adding observable
                                builder.add_to_bundle([stix_observable])
                                observable_id = stix_observable["id"]
                                # Initialize external reference for sightings
                                sighting_ext_refs = [cti_external_reference]
                                # Handle reputation
                                if reputation in self.indicator_create_from:
                                    pattern = f"[ipv4-addr:value = '{ip}']"
                                    indicator = builder.add_indicator_based_on(
                                        observable_id,
                                        stix_observable,
                                        pattern,
                                        markings=[self.tlp] if self.tlp else None,
                                    )
                                # Handle mitre_techniques
                                attack_patterns = []
                                for mitre_technique in mitre_techniques:
                                    mitre_external_reference = (
                                        builder.create_external_ref_for_mitre(
                                            mitre_technique
                                        )
                                    )
                                    sighting_ext_refs.append(mitre_external_reference)
                                    # Create attack pattern
                                    if (
                                        indicator
                                        and self.attack_pattern_create_from_mitre
                                    ):
                                        attack_pattern = (
                                            builder.add_attack_pattern_for_mitre(
                                                mitre_technique=mitre_technique,
                                                markings=(
                                                    [self.tlp] if self.tlp else None
                                                ),
                                                indicator=indicator,
                                                external_references=[
                                                    mitre_external_reference
                                                ],
                                            )
                                        )
                                        attack_patterns.append(attack_pattern.id)
                                # Handle CVEs
                                for cve in cves:
                                    # Create vulnerability
                                    builder.add_vulnerability_from_cve(
                                        cve,
                                        markings=[self.tlp] if self.tlp else None,
                                        observable_id=observable_id,
                                    )
                                # Handle target countries
                                builder.handle_target_countries(
                                    attack_patterns=attack_patterns,
                                    markings=[self.tlp] if self.tlp else None,
                                    observable_id=(
                                        observable_id
                                        if self.create_targeted_countries_sigthings
                                        else None
                                    ),
                                )
                                # Add note
                                if self.create_note:
                                    builder.add_note(
                                        observable_id=stix_observable.id,
                                        markings=[self.tlp] if self.tlp else None,
                                    )
                                # Create sightings relationship between CrowdSec organisation and observable
                                if self.create_sighting:
                                    builder.add_sighting(
                                        observable_id=stix_observable.id,
                                        markings=[self.tlp] if self.tlp else None,
                                        sighting_ext_refs=sighting_ext_refs,
                                        indicator=indicator if indicator else None,
                                    )

                                bundle_objects.extend(builder.get_bundle())
                                batch_bundle_objects.extend(bundle_objects)

                                end_time = time.time()
                                time_taken = end_time - start_time
                                self.helper.log_debug(
                                    f"Processing IP {counter}/{ip_count}: {ip} took {time_taken:.4f} seconds"
                                )
                            if batch_labels:
                                for label in batch_labels:
                                    self.helper.api.label.read_or_create_unchecked(
                                        value=label["value"], color=label["color"]
                                    )
                            batch_end_time = time.time()
                            batch_time_taken = batch_end_time - batch_start_time
                            time_from_enrichment_start = (
                                batch_end_time - start_enrichment_time
                            )
                            remaining_time = (
                                time_from_enrichment_start / batch_index
                            ) * (total_batch_count - batch_index)
                            self.helper.log_info(
                                f"Processing batch {batch_index}/{total_batch_count} "
                                f"took {batch_time_taken:.4f} seconds"
                            )
                            if batch_index % 5 == 0:
                                self.helper.log_info(
                                    (
                                        f"Elapsed time since start of enrichment: "
                                        f"{self.format_duration(int(time_from_enrichment_start))} / "
                                        f"Estimated time remaining: {self.format_duration(int(remaining_time))}"
                                    )
                                )
                            if batch_bundle_objects:
                                bundle_start_time = time.time()
                                self.helper.log_info(
                                    f"Start sending {len(batch_bundle_objects)} bundles to to OpenCTI"
                                )
                                # bundle = stix2.Bundle(batch_bundle_objects, allow_custom=True)
                                # bundle_json = bundle.serialize()
                                bundle_json = self.helper.stix2_create_bundle(
                                    batch_bundle_objects
                                )
                                # Sending the bundle
                                self.helper.send_stix2_bundle(
                                    bundle_json,
                                    update=self.update_existing_data,
                                    work_id=work_id,
                                )
                                bundle_end_time = time.time()
                                bundle_time_taken = bundle_end_time - bundle_start_time
                                self.helper.log_info(
                                    f"Sending bundles took {bundle_time_taken:.4f} seconds"
                                )
                            if i == 0:
                                # Store the last_run on first loop to avoid multiple runs
                                self.helper.set_state({"last_run": run_start_timestamp})

                        # Store the current run_start_timestamp as a last run
                        self.helper.set_state({"last_run": run_start_timestamp})
                        message = (
                            "CrowdSec import connector successfully run, last_run stored as "
                            + str(run_start_timestamp)
                        )
                        self.helper.log_info(message)
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
                    next_run = last_run + timedelta(seconds=self.get_interval())
                    self.helper.log_info(
                        f"Connector will not run, next run at: {next_run}"
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
