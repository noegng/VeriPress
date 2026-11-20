"""Content addresses for published data (decisions.md Q9). OWNER: Dev A.

CIDv1, codec raw (0x55), multihash sha2-256 (0x12, 32 bytes), multibase base32 lower ("b").
For data up to one IPFS block (<= 1 MiB) this is exactly what `ipfs add --cid-version 1
--raw-leaves` returns; larger files are chunked by IPFS into a DAG with another root CID,
so in production they would be published as a DAG (or pinned under this raw CID as a block).
Either way the CID is a sha256 commitment any mirror can be checked against.
"""

from __future__ import annotations

import base64
import hashlib
import json


def cid_v1_raw(data: bytes) -> str:
    multihash = bytes([0x12, 0x20]) + hashlib.sha256(data).digest()
    return "b" + base64.b32encode(bytes([0x01, 0x55]) + multihash).decode().lower().rstrip("=")


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
