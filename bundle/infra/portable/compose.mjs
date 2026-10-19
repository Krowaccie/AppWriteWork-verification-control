import {mcpPolicy} from './mcp-profile.mjs';
import { buildCompose } from './appwrite-compose.mjs';
export const OWNER = 'io.appwritework.portable';
export const VOLUMES = ['postgresql','redis','clickhouse','uploads','imports','cache','config','certificates','functions','sites','builds','app-data','temporal-data'];
export function compose(profile, pins) {
  if (!/^sm[89]-[a-z0-9-]{6,36}$/.test(profile.project)) throw new Error('PORTABLE_PROJECT_INVALID');
  const c = buildCompose({project:profile.project,runId:profile.project},pins);
  const labels = {[OWNER]:profile.project};
  c.networks = {lab:{name:profile.project+'-network',labels,...(profile.cloudBlocked?{internal:true}:{})},private:{internal:true,labels}};
  if(profile.cloudBlocked)c.networks.ingress={labels};
  for (const v of Object.values(c.volumes)) v.labels=labels;
  const s=c.services;
  for (const [name,v] of Object.entries(s)) {
    v.labels=labels;v.restart='unless-stopped';v.networks=['private'];
    v.mem_limit=name==='clickhouse'?'2g':name==='postgresql'?'1g':'768m';v.cpus=2;
  }
  for (const n of ['appwrite','worker','executor','orchestrator']) s[n].networks.push('lab');
  delete s.appwrite.ports;
  // Single-host trust boundary: API/runtime network separated from provider databases.
  for (const n of ['appwrite','worker']) Object.assign(s[n].environment,{
    _APP_OPTIONS_ABUSE:'enabled',_APP_CONSOLE_SESSION_ALERTS:'disabled',
    _APP_DOMAIN:'localhost',_APP_CONSOLE_HOSTNAMES:'localhost,127.0.0.1',
    _APP_COMPUTE_CPUS:'1',_APP_COMPUTE_MEMORY:'256',_APP_WORKER_MAX_COROUTINES:'16',
  });
  s.redis.command=['redis-server','--maxmemory','256mb','--maxmemory-policy','noeviction','--appendonly','yes'];
  s.postgresql.command=['postgres','-c','max_slot_wal_keep_size=512MB'];
  s.postgresql.init=true;
  s.worker.mem_limit='1g';s.appwrite.mem_limit='1g';
  const health=test=>({test,interval:'3s',timeout:'3s',retries:60,start_period:'15s'});
  const service=(image,extra={})=>({image,labels,networks:['private'],restart:'unless-stopped',
    logging:{driver:'json-file',options:{'max-size':'5m','max-file':'2'}},mem_limit:'512m',cpus:2,...extra});
  const file=(source,target,ro=true)=>({type:'bind',source:'./'+source,target,read_only:ro});
  const secret=n=>file('secrets/'+n,'/run/secrets/'+n);
  for (const [name,user,db,target] of [
    ['app-postgres','salmora_operator','salmora','/var/lib/postgresql'],
    ['temporal-postgres','temporal_operator','temporal','/var/lib/postgresql/data']]) {
    s[name]=service(pins[name].reference,{
      environment:{POSTGRES_USER:user,POSTGRES_DB:db,POSTGRES_PASSWORD_FILE:'/run/secrets/'+name+'.password'},
      volumes:[(name==='app-postgres'?'app-data:':'temporal-data:')+target,secret(name+'.password')],
      healthcheck:health(['CMD','pg_isready','-U',user,'-d',db]),mem_limit:'1g',
      init:true,command:['postgres','-c','max_connections=80','-c','shared_buffers=128MB','-c','max_slot_wal_keep_size=512MB'],
    });
  }
  s['app-postgres'].networks.push('lab');
  s['app-postgres'].entrypoint=['/bin/bash','/portable/postgres-tls.sh'];
  s['app-postgres'].volumes.push(file('config/postgres-tls.sh','/portable/postgres-tls.sh'),file('config/pg_hba.conf','/portable/pg_hba.conf'),
    secret('server.crt'),secret('server.key'));
  s['app-postgres'].command.push('-c','ssl=on','-c','ssl_cert_file=/var/lib/postgresql/tls/server.crt',
    '-c','ssl_key_file=/var/lib/postgresql/tls/server.key','-c','hba_file=/portable/pg_hba.conf');
  s['temporal-postgres'].volumes.push(file('config/temporal-init.sh','/docker-entrypoint-initdb.d/temporal-init.sh'),
    secret('temporal-migrator.password'),secret('temporal-runtime.password'));
  s['temporal-schema']=service(pins.admin.reference,{
    restart:'no',profiles:['operator'],entrypoint:['/bin/sh','/portable/temporal-schema.sh'],
    volumes:[file('config/temporal-schema.sh','/portable/temporal-schema.sh'),secret('temporal-migrator.password')],
    depends_on:{'temporal-postgres':{condition:'service_healthy'}}});
  s.temporal=service(pins.temporal.reference,{
    mem_limit:'1g',entrypoint:['/bin/sh','/portable/temporal-server.sh'],
    command:['/etc/temporal/entrypoint.sh'],
    environment:{DB:'postgres12',DB_PORT:'5432',POSTGRES_USER:'temporal_runtime',POSTGRES_SEEDS:'temporal-postgres',BIND_ON_IP:'0.0.0.0'},
    volumes:[file('config/temporal-server.sh','/portable/temporal-server.sh'),secret('temporal-runtime.password')],
    depends_on:{'temporal-postgres':{condition:'service_healthy'}},
    healthcheck:health(['CMD','nc','-z','127.0.0.1','7233'])});
  s['temporal-namespace']=service(pins.admin.reference,{
    restart:'no',profiles:['operator'],entrypoint:['/bin/sh','/portable/temporal-namespace.sh'],
    volumes:[file('config/temporal-namespace.sh','/portable/temporal-namespace.sh')]});
  s['execution-worker']=service(profile.workerImage || 'salmora-portable-worker:'+profile.project,{
    profiles:['execution'],networks:['private','lab'],mem_limit:'768m',stop_grace_period:'40s',
    environment:{SALMORA_WORKER_CONFIG:'/run/worker/worker.private.json',PYTHONDONTWRITEBYTECODE:'1'},
    volumes:[file('worker','/run/worker'),file('config/health.py','/portable/health.py')],
    healthcheck:{test:['CMD','python','/portable/health.py'],interval:'30s',timeout:'10s',retries:3,start_period:'20s'},
    depends_on:{temporal:{condition:'service_healthy'},'app-postgres':{condition:'service_healthy'},appwrite:{condition:'service_healthy'}},
  });
  s.gateway=service(profile.product?.webImage || pins.caddy.reference,{
    networks:profile.cloudBlocked?['lab','ingress']:['lab'],mem_limit:'128m',read_only:true,tmpfs:['/data','/config','/tmp'],
    ports:[{target:443,published:String(profile.port??0),host_ip:'127.0.0.1',protocol:'tcp'}],
    volumes:[file('config/Caddyfile','/etc/caddy/Caddyfile'),secret('server.crt'),secret('server.key')],
    healthcheck:health(['CMD','wget','-q','--spider','http://127.0.0.1:8080/healthz']),
    depends_on:{appwrite:{condition:'service_healthy'}},
  });
  if (mcpPolicy(profile)) {
    s.mcp=service(profile.product.webImage,{
      networks:['lab'],mem_limit:'256m',cpus:1,init:true,read_only:true,
      user:'1000:1000',cap_drop:['ALL'],security_opt:['no-new-privileges:true'],
      entrypoint:['node','/opt/apps/mcp-bridge/src/remote.js'],command:[],
      environment:{HOST:'0.0.0.0',PORT:'8090',
        // Keep Compose interpolation from changing literal client names/callback paths.
        SALMORA_MCP_OAUTH_CONFIG:JSON.stringify(profile.product.mcpOAuth).replaceAll('$', '\\u0024'),
        SALMORA_APPWRITE_ENDPOINT:'http://appwrite/v1',
        SALMORA_APPWRITE_PROJECT_ID:profile.product.projectId},
      healthcheck:health(['CMD','node','-e',"fetch('http://127.0.0.1:8090/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]),
      stop_grace_period:'60s',depends_on:{appwrite:{condition:'service_healthy'}},
    });
    s.gateway.depends_on.mcp={condition:'service_healthy'};
  }
  for (const v of ['app-data','temporal-data']) c.volumes[v]={name:profile.project+'-'+v,labels};
  return c;
}
