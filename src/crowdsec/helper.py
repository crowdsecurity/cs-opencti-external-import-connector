# -*- coding: utf-8 -*-
"""CrowdSec helper module."""
import os.path
import re
import hashlib
import io
import tarfile
import json
from typing import Dict, Any, Optional
import shutil


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
