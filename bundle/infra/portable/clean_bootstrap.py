"""Atomic clean bootstrap and read-only verification of an owned LOCAL SQL target."""
import json
import re
import sys
from pathlib import Path

from appwritework_backend.sql.migration import _migrations, migration_manifest

ROOT = Path('/run/portable')
STRUCTURAL = {'tenant_guards', 'access_memberships', 'execution_limits_policy', 'execution_budget_accounts'}

def require(value, code):
    if not value:
        raise ValueError(code)

def expected_tables():
    return {'salmora_schema_migrations'} | {
        name for _, _, _, source in _migrations()
        for name in re.findall(r'CREATE TABLE\s+([a-z_]+)', source)
    }

def system_guards():
    """Exact structural identities declared by the selected migration source."""
    guards = [guard for _, _, _, source in _migrations()
              for guard in re.findall(r"INSERT INTO\s+tenant_guards\s*\(tenant_id\)\s+VALUES\s*\('([^']+)'\)", source)]
    require(guards and len(set(guards)) == len(guards) and all(value.startswith('system:') for value in guards),
            'CLEAN_SYSTEM_GUARD_CONTRACT')
    return sorted(guards)


def inspect(cx, c, *, empty=False):
    from psycopg import sql
    tables = {r['tablename'] for r in cx.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname='salmora_app'")}
    require(tables == expected_tables(), 'CLEAN_SQL_SCHEMA_DRIFT')
    ledger = cx.execute('SELECT name,sha256 FROM salmora_schema_migrations ORDER BY name').fetchall()
    require(ledger == migration_manifest(), 'CLEAN_SQL_MIGRATION_DRIFT')
    counts = {t: cx.execute(sql.SQL('SELECT count(*) AS n FROM {}').format(sql.Identifier(t))).fetchone()['n']
              for t in sorted(tables - {'salmora_schema_migrations'})}
    expected_guards=system_guards()
    expected_count=lambda t: (len(expected_guards)+(0 if empty else 1)) if t=='tenant_guards' else (0 if empty or t not in STRUCTURAL else 1)
    mismatched={t:n for t,n in counts.items() if n != expected_count(t)}
    require(not mismatched, 'CLEAN_SQL_NOT_EMPTY:'+json.dumps(mismatched,sort_keys=True))
    guards=expected_guards+([] if empty else [c['tenantId']])
    require(cx.execute('SELECT tenant_id FROM tenant_guards ORDER BY tenant_id').fetchall() ==
            [{'tenant_id':v} for v in sorted(guards)], 'CLEAN_TENANT_DRIFT')
    if not empty:
        require(cx.execute('SELECT tenant_id,principal_id,state,revision FROM access_memberships').fetchall() ==
            [dict(tenant_id=c['tenantId'],principal_id=c['ownerId'],state='active',revision=1)], 'CLEAN_MEMBERSHIP_DRIFT')
        require(cx.execute('SELECT * FROM execution_limits_policy').fetchall() == [dict(tenant_id=c['tenantId'],
            max_tenant_active=6,max_root_active=4,max_parent_active=4,max_root_total=100,root_budget_usd_micros=0,revision=1)], 'CLEAN_POLICY_DRIFT')
        require(cx.execute('SELECT * FROM execution_budget_accounts').fetchall() == [dict(tenant_id=c['tenantId'],
            payer_principal_id=c['ownerId'],limit_usd_micros=0,reserved_usd_micros=0,consumed_usd_micros=0,revision=1)], 'CLEAN_BUDGET_DRIFT')
    return {'tables':len(tables),'migrations':len(ledger),'emptyProductTables':len(counts)-len(STRUCTURAL),
            'structuralRows':len(expected_guards)+(0 if empty else 4),'importedRows':0,'budgetUsdMicros':0}

def main(action):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    require(action in {'bootstrap','verify'}, 'CLEAN_SQL_ACTION')
    profile=json.loads((ROOT/'profile.json').read_text())
    c=json.loads((ROOT/'private/appwrite.private.json').read_text())
    require(profile.get('deploymentBinding') and c.get('cleanBinding')==profile['deploymentBinding']
            and not c.get('source') and not c.get('guestId'), 'CLEAN_SQL_BINDING')
    base=dict(host='app-postgres',port=5432,dbname='salmora',sslmode='verify-full',sslrootcert=str(ROOT/'secrets/ca.crt'))
    with psycopg.connect(**base,user='salmora_migrator',password=(ROOT/'secrets/app-migrator.password').read_text().strip(),row_factory=dict_row) as cx:
        cx.execute('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE' + (' READ ONLY' if action=='verify' else ''))
        cx.execute('SET LOCAL search_path TO salmora_app')
        replay=False
        if action=='bootstrap':
            # No runtime exists yet. Lock every current application table during the empty check and all four inserts.
            cx.execute(sql.SQL('LOCK TABLE {} IN EXCLUSIVE MODE').format(sql.SQL(',').join(map(sql.Identifier,sorted(expected_tables())))))
            replay=bool(cx.execute('SELECT 1 FROM tenant_guards WHERE tenant_id=%s',(c['tenantId'],)).fetchone())
            if not replay:
                inspect(cx,c,empty=True)
                cx.execute('INSERT INTO tenant_guards (tenant_id) VALUES (%s)',(c['tenantId'],))
                cx.execute("INSERT INTO access_memberships (tenant_id,principal_id,state,revision) VALUES (%s,%s,'active',1)",(c['tenantId'],c['ownerId']))
                cx.execute('INSERT INTO execution_limits_policy VALUES (%s,6,4,4,100,0,1)',(c['tenantId'],))
                cx.execute('INSERT INTO execution_budget_accounts (tenant_id,payer_principal_id,limit_usd_micros,revision) VALUES (%s,%s,0,1)',(c['tenantId'],c['ownerId']))
        result=inspect(cx,c)
    with psycopg.connect(**base,user='salmora_runtime',password=(ROOT/'secrets/app-runtime.password').read_text().strip(),row_factory=dict_row) as cx:
        role=cx.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,has_schema_privilege(current_user,'salmora_app','CREATE') AS ddl,"
            "has_table_privilege(current_user,'salmora_app.salmora_schema_migrations','INSERT') AS ledger_write,"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS tls FROM pg_roles WHERE rolname=current_user").fetchone()
        require(role==dict(rolsuper=False,rolcreatedb=False,rolcreaterole=False,ddl=False,ledger_write=False,tls=True),'CLEAN_SQL_RUNTIME_PRIVILEGES')
    print(json.dumps(dict(status='PASS',action=action,replay=replay,**result,runtime=role)))

if __name__=='__main__':
    try: main(sys.argv[1])
    except Exception as error:
        print(json.dumps({'status':'FAIL','code':str(error) if isinstance(error,ValueError) else type(error).__name__,
                          'sqlstate':getattr(error,'sqlstate',None)}))
        raise SystemExit(1)
