# -*- coding: utf-8 -*-
"""CrowdSec helper module."""
import datetime
import os.path
import re
import hashlib
import io
import tarfile
import json
from typing import Dict, Any, Optional
import shutil

from .constants import LAST_ENRICHMENT_PATTERN


def clean_config(value: str) -> str:
    """Clean a string configuration value.

    Args:
        value (str): The value to clean.

    Returns:
        str: The cleaned value.
    """
    if isinstance(value, str):
        return re.sub(r"[\"']", "", value)

    return ""


def verify_checksum(
    filename: str, expected_checksum: str, checksum_type: str = "sha256"
):
    hash_func = hashlib.new(checksum_type)
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest() == expected_checksum


def read_cti_dump(dump_path: str) -> Dict[str, Any]:
    result = {}
    with open(dump_path, "rb") as f:
        file_obj = io.BytesIO(f.read())
        with tarfile.open(fileobj=file_obj, mode="r:gz") as tar:
            for item in tar:
                if item.isfile():
                    extracted_file = tar.extractfile(item.name)
                    if extracted_file is not None:
                        file_content = json.load(extracted_file)
                        for info in file_content:
                            if "ip" in info:
                                result[info["ip"]] = info

    return result


def delete_folder(folder: Optional[str]) -> None:
    """Delete a folder.

    Args:
        folder (str): The folder to delete.
    """
    try:
        if folder and os.path.exists(folder):
            shutil.rmtree(folder)
    except FileNotFoundError:
        pass
    except Exception as e:
        raise e


def convert_timestamp_to_utc_iso(timestamp: int) -> str:
    """Convert a timestamp to UTC ISO format.

    Args:
        timestamp (str): The timestamp to convert.

    Returns:
        str: The converted timestamp.
    """
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()


def convert_utc_iso_to_timestamp(iso: str) -> int:
    """Convert a UTC ISO format to a timestamp.

    Args:
        iso (str): The UTC ISO format to convert.

    Returns:
        int: The converted timestamp.
    """
    return int(datetime.datetime.fromisoformat(iso).timestamp())


def handle_observable_description(
    timestamp: int, stix_observable: Optional[Dict]
) -> Dict[str, Any]:
    """Handle the observable description.

    We are saving the current timestamp in description to track the last time the observable was enriched by CrowdSec.

    Args:
        timestamp (int): The current timestamp.
        stix_observable (Dict): The STIX observable to handle.

    Returns:
        Dict: The updated description with current timestamp and the time since the last enrichment.
    """
    description = ""
    time_since_last_enrichment = -1  # -1 means no previous enrichment
    if stix_observable and stix_observable["x_opencti_description"]:
        sub_pattern = r"`" + re.escape(LAST_ENRICHMENT_PATTERN) + r".*`"
        search_pattern = (
            re.escape(LAST_ENRICHMENT_PATTERN) + r"([\d-]+T[\d:]+[+-][\d:]+)"
        )
        match = re.search(search_pattern, stix_observable["x_opencti_description"])
        if match:
            time_since_last_enrichment = timestamp - convert_utc_iso_to_timestamp(
                match.group(1)
            )
        description = re.sub(
            sub_pattern + r"|\n\n" + sub_pattern,
            "",
            stix_observable["x_opencti_description"],
        )
    description += (
        f"\n\n`{LAST_ENRICHMENT_PATTERN}{convert_timestamp_to_utc_iso(timestamp)}`"
    )

    return {
        "description": description,
        "time_since_last_enrichment": time_since_last_enrichment,
    }
