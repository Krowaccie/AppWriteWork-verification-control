"""Readiness dependencies; business health is qualified by native acceptance."""
import json
import os
import socket
from appwritework_backend.sql import SqlConfig
try:
    config=json.load(open(os.environ["SALMORA_WORKER_CONFIG"],encoding="utf-8"))
    host,port=config["temporal"]["target"].rsplit(":",1)
    with socket.create_connection((host,int(port)),timeout=2): pass
    with SqlConfig.from_mapping(config["sql"]).connect() as db:
        db.execute("SELECT 1").fetchone()
except Exception:
    raise SystemExit(1)
