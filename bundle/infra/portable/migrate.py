"""Explicit operator command. Runtime processes never provision SQL or run DDL."""
import json
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from appwritework_backend.sql import SqlStore, apply_migrations

def main():
    root = Path("/run/portable")
    password = lambda name: (root / "secrets" / (name + ".password")).read_text().strip()
    base = dict(host="app-postgres", port=5432, dbname="salmora", sslmode="verify-full",
                sslrootcert=str(root / "secrets/ca.crt"))
    with psycopg.connect(**base, user="salmora_operator", password=password("app-postgres"), autocommit=True) as cx:
        for role, key in (("salmora_migrator", "app-migrator"), ("salmora_runtime", "app-runtime")):
            exists = cx.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
            if not exists:
                cx.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE").format(
                    sql.Identifier(role), sql.Literal(password(key))))
        cx.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        cx.execute("GRANT CREATE ON DATABASE salmora TO salmora_migrator")
    migration = {**base, "user": "salmora_migrator", "password": password("app-migrator")}
    store = SqlStore.from_config(migration, schema="salmora_app")
    changes = apply_migrations(store)
    with psycopg.connect(**migration, autocommit=True) as cx:
        cx.execute("GRANT USAGE ON SCHEMA salmora_app TO salmora_runtime")
        cx.execute("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA salmora_app TO salmora_runtime")
        cx.execute("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA salmora_app TO salmora_runtime")
        cx.execute("REVOKE ALL ON salmora_app.salmora_schema_migrations FROM salmora_runtime")
        cx.execute("REVOKE DELETE,TRUNCATE ON salmora_app.tenant_guards FROM salmora_runtime")
    with psycopg.connect(**base, user="salmora_runtime", password=password("app-runtime"), row_factory=dict_row) as cx:
        row = cx.execute("SELECT r.rolsuper, r.rolcreatedb, r.rolcreaterole, "
            "has_schema_privilege(current_user,'salmora_app','CREATE') AS ddl, "
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS tls "
            "FROM pg_roles r WHERE rolname=current_user").fetchone()
        assert row == dict(rolsuper=False,rolcreatedb=False,rolcreaterole=False,ddl=False,tls=True)
    print(json.dumps({"status":"PASS","migrations":len(changes),"roles":"operator/migrator/runtime","runtime":row}))

if __name__ == "__main__":
    try: main()
    except Exception as e:
        print(json.dumps({"status":"FAIL","error":type(e).__name__,"code":getattr(e,"code",None),"sqlstate":getattr(e,"sqlstate",None)}))
        raise SystemExit(1)
