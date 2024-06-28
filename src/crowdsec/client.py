# -*- coding: utf-8 -*-
"""CrowdSec client module."""

import itertools
from dataclasses import dataclass
from time import sleep
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper


class QuotaExceedException(Exception):
    pass


@dataclass
class CrowdSecClient:
    """CrowdSec client."""

    helper: OpenCTIConnectorHelper
    url: str
    api_key: str

    @staticmethod
    def download_file(url: str, destination: str):
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(destination, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return destination

    def get_crowdsec_dump(self):
        for i in itertools.count(1, 1):
            resp = requests.get(
                urljoin(self.url, "dump"),
                headers={
                    "x-api-key": self.api_key,
                    "User-Agent": "crowdsec-import-opencti/v0.0.1",
                },
            )
            if resp.status_code == 429:
                raise QuotaExceedException(
                    (
                        "Quota exceeded for CrowdSec CTI API. "
                        "Please visit https://www.crowdsec.net/pricing to upgrade your plan."
                    )
                )
            elif resp.status_code == 200:
                return resp.json()
            else:
                self.helper.log_debug(f"CrowdSec CTI request {resp.url}")
                self.helper.log_debug(f"CrowdSec CTI headers {resp.request.headers}")
                self.helper.log_info(f"CrowdSec CTI response {resp.text}")
                self.helper.log_warning(
                    f"CrowdSec CTI returned {resp.status_code} response status code. Retrying..."
                )
            sleep(2**i)
