"""
Cloud storage exposure checks: S3/Azure buckets, Firebase.

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

_FIREBASE_URL_PATTERN = re.compile(
    r"https?://([a-z0-9\-]+)\.firebaseio\.com", re.IGNORECASE
)


async def check_firebase_exposure(js_url: str) -> dict | None:
    """
    Downloads a JS bundle looking for a hardcoded Firebase databaseURL
    (a routine finding - Firebase config is client-side by design). The
    actual check is whether that database allows anonymous reads: if
    appending /.json to the databaseURL returns real data instead of
    `null` or a permission-denied error, the whole dataset is public.
    """
    if not js_url.lower().split("?")[0].endswith(".js"):
        return None

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(js_url)
    except httpx.HTTPError as exc:
        logger.info("detective: firebase check fetch failed for %s: %s", js_url, exc)
        return None

    if resp.status_code != 200:
        return None

    matches = set(_FIREBASE_URL_PATTERN.findall(resp.text))
    if not matches:
        return None

    logger.info(
        "detective: checking Firebase exposure for %d project(s) found in %s",
        len(matches), js_url,
    )
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            for project in list(matches)[:2]:
                db_url = f"https://{project}.firebaseio.com/.json"
                try:
                    db_resp = await client.get(db_url)
                except httpx.HTTPError:
                    continue
                body = db_resp.text.strip()
                if db_resp.status_code == 200 and body and body != "null":
                    preview = body[:200].replace("\n", " ")
                    return {
                        "vuln_type": "exposed_firebase_database",
                        "severity": "critical",
                        "evidence": (
                            f"Firebase project '{project}' (found in {js_url}) allows "
                            f"anonymous reads at {db_url}. Data preview: {preview}..."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: firebase DB check failed: %s", exc)
    return None


_BUCKET_REFERENCE_RE = re.compile(
    r"(?:([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"
    r"|s3\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"|storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])"
    r"|([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com)",
    re.IGNORECASE,
)
_BUCKET_LISTING_SIGNATURES = ["<ListBucketResult", "\"kind\": \"storage#objects\"", "\"items\":"]


async def check_cloud_storage_bucket_exposure(url: str) -> dict | None:
    """
    Scans a page's body for S3/GCS bucket references (in script tags,
    image URLs, config blobs - anywhere a bucket name shows up in
    plaintext), then issues a direct, read-only GET against that
    bucket's own listing endpoint. Fires only if the bucket responds
    with an actual object listing body (ListBucketResult / GCS's
    "items" JSON) - a 403 AccessDenied response, which is the normal/
    secure case, does not match and is correctly ignored.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            seen_buckets: set[str] = set()
            for match in _BUCKET_REFERENCE_RE.finditer(body):
                bucket_name = next((g for g in match.groups() if g), None)
                if not bucket_name or bucket_name.lower() in seen_buckets:
                    continue
                seen_buckets.add(bucket_name.lower())

                for listing_url in (
                    f"https://{bucket_name}.s3.amazonaws.com/",
                    f"https://storage.googleapis.com/{bucket_name}/",
                ):
                    try:
                        listing_resp = await client.get(listing_url)
                    except httpx.HTTPError:
                        continue
                    listing_body = listing_resp.text[:3000]
                    if any(sig in listing_body for sig in _BUCKET_LISTING_SIGNATURES):
                        return {
                            "vuln_type": "publicly_listable_cloud_storage_bucket",
                            "severity": "high",
                            "evidence": (
                                f"Bucket '{bucket_name}' (referenced on {url}) is publicly "
                                f"listable at {listing_url} - returned an actual object "
                                f"listing instead of an access-denied response."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: cloud storage bucket check failed for %s: %s", url, exc)
    return None


_AZURE_BLOB_REFERENCE_RE = re.compile(
    r"([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.blob\.core\.windows\.net/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])",
    re.IGNORECASE,
)


async def check_azure_blob_public_exposure(url: str) -> dict | None:
    """
    Same technique and proof bar as check_cloud_storage_bucket_exposure
    (batch 9), targeting Azure Blob Storage instead of S3/GCS: scans
    page content for account.blob.core.windows.net/container
    references, then issues a direct, read-only container-listing
    request. Only fires on an actual object listing
    (<EnumerationResults>), not just a reachable container.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            seen = set()
            for account, container in _AZURE_BLOB_REFERENCE_RE.findall(body):
                key = f"{account}/{container}".lower()
                if key in seen:
                    continue
                seen.add(key)
                listing_url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
                try:
                    listing_resp = await client.get(listing_url)
                except httpx.HTTPError:
                    continue
                if "<EnumerationResults" in listing_resp.text[:2000]:
                    return {
                        "vuln_type": "publicly_listable_azure_blob_container",
                        "severity": "high",
                        "evidence": (
                            f"Azure Blob container '{container}' on account '{account}' "
                            f"(referenced on {url}) is publicly listable at {listing_url} - "
                            f"returned an actual <EnumerationResults> object listing."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Azure blob check failed for %s: %s", url, exc)
    return None


_FIREBASE_PROJECT_RE = re.compile(r"([a-z0-9-]+)\.firebaseio\.com", re.IGNORECASE)


async def check_firebase_realtime_db_open_rules(url: str) -> dict | None:
    """
    Complements check_firebase_exposure (batch 1, which likely checks
    for exposed Firebase config in JS) with a direct test of whether
    the Realtime Database's security rules allow public read: extracts
    a project name from any firebaseio.com reference on the page, then
    requests https://PROJECT.firebaseio.com/.json directly. A JSON
    response containing real data (not null, not a permission-denied
    error) proves open read rules.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            match = _FIREBASE_PROJECT_RE.search(body)
            if not match:
                return None
            project = match.group(1)
            db_url = f"https://{project}.firebaseio.com/.json"
            try:
                db_resp = await client.get(db_url)
            except httpx.HTTPError:
                return None
            try:
                data = db_resp.json()
            except Exception:
                return None
            if db_resp.status_code == 200 and data is not None and not (
                isinstance(data, dict) and "error" in data
            ):
                return {
                    "vuln_type": "firebase_realtime_db_open_read",
                    "severity": "high",
                    "evidence": (
                        f"{db_url} (project referenced on {url}) returned real, non-null "
                        f"data with no error - the Realtime Database's security rules allow "
                        f"public read access to the entire database."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: Firebase RTDB check failed for %s: %s", url, exc)
    return None


_S3_OBJECT_KEY_RE = re.compile(r"<Key>([^<]+)</Key>")
_GCS_OBJECT_NAME_RE = re.compile(r'"name"\s*:\s*"([^"]+)"')


async def check_storage_bucket_object_extraction(url: str) -> dict | None:
    """
    Complements check_cloud_storage_bucket_exposure (batch 10), which
    stops at "the listing endpoint returned a listing" - true, but a
    listing with zero real business risk if the bucket happens to be
    empty. This parses the SAME listing response for a real object key/
    name and issues one more read-only GET for that exact object,
    confirming it downloads (status 200, non-empty body) rather than
    just appearing in a directory index. Never writes, deletes, or
    uploads anything - strictly a second read.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            seen_buckets: set[str] = set()
            for match in _BUCKET_REFERENCE_RE.finditer(body):
                bucket_name = next((g for g in match.groups() if g), None)
                if not bucket_name or bucket_name.lower() in seen_buckets:
                    continue
                seen_buckets.add(bucket_name.lower())

                for listing_url, is_s3 in (
                    (f"https://{bucket_name}.s3.amazonaws.com/", True),
                    (f"https://storage.googleapis.com/{bucket_name}/", False),
                ):
                    try:
                        listing_resp = await client.get(listing_url)
                    except httpx.HTTPError:
                        continue
                    listing_body = listing_resp.text[:20000]
                    if not any(sig in listing_body for sig in _BUCKET_LISTING_SIGNATURES):
                        continue

                    object_key = None
                    if is_s3:
                        m = _S3_OBJECT_KEY_RE.search(listing_body)
                        object_key = m.group(1) if m else None
                    else:
                        m = _GCS_OBJECT_NAME_RE.search(listing_body)
                        object_key = m.group(1) if m else None
                    if not object_key:
                        continue

                    object_url = listing_url + object_key
                    try:
                        obj_resp = await client.get(object_url)
                    except httpx.HTTPError:
                        continue
                    if obj_resp.status_code == 200 and len(obj_resp.content) > 0:
                        return {
                            "vuln_type": "publicly_downloadable_cloud_storage_object",
                            "severity": "high",
                            "evidence": (
                                f"Bucket '{bucket_name}' (referenced on {url}) is not just "
                                f"listable but a real object from its listing - "
                                f"{object_key!r} - downloaded successfully at {object_url} "
                                f"({len(obj_resp.content)} bytes, "
                                f"content-type {obj_resp.headers.get('content-type', 'unknown')}) "
                                f"- confirmed data exposure, not just an empty/theoretical "
                                f"listing."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: storage bucket object extraction check failed for %s: %s", url, exc)
    return None


