// Pure preparation: no DNS, ACME, SMTP or deployment calls happen here.
import fs from 'node:fs/promises';
import {mcpRoutes,mcpPolicy} from './mcp-profile.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {compose, OWNER} from './compose.mjs';
import {hold} from './upgrade-contract.mjs';

// Pinned Appwrite 2.4 worker names. The `worker` shell wrapper always adds `all`;
// invoke PHP directly so certificates cannot compete with the Caddy TLS owner.
export const PUBLIC_WORKERS=Object.freeze(['stats-usage','stats-resources','webhooks','deletes','databases','builds','jobs','screenshots','executions','functions','mails','notifications','messaging','migrations']);
const requireThat=(value,code)=>{if(!value)throw new Error(code);};

export const MAILPIT = 'axllent/mailpit@sha256:df6c2541907e1be6fac21f509927cf6ed771617a1f4b361ef66d97bd05593d2d';
const dns = v => typeof v === 'string' && v.length < 254 && v.includes('.') &&
  v.split('.').every(x => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x));
const email = v => typeof v === 'string' && /^[a-zA-Z0-9._+-]+@[a-z0-9.-]+$/.test(v) && dns(v.split('@')[1]);
export function validate(config) {
  requireThat(config?.version === 1 && ['rehearsal','public'].includes(config.mode), 'PUBLIC_PROFILE_INVALID');
  let u; try { u = new URL(config.origin); } catch { throw new Error('PUBLIC_ORIGIN_INVALID'); }
  requireThat(u.protocol === 'https:' && !u.port && !u.username && !u.password &&
    u.pathname === '/' && !u.search && !u.hash && config.origin === u.origin && dns(u.hostname), 'PUBLIC_ORIGIN_INVALID');
  const lab = config.mode === 'rehearsal';
  requireThat(lab ? u.hostname === 'salmora.test' : !/\.(test|invalid|localhost|local|example)$/.test(u.hostname), 'PUBLIC_HOST_INVALID');
  requireThat(email(config.sender?.address) && /^[a-zA-Z0-9 ._-]{1,64}$/.test(config.sender?.name), 'PUBLIC_SENDER_INVALID');
  requireThat(['tls','ssl'].includes(config.smtp?.security) && Number.isInteger(config.smtp.port) && config.smtp.port > 0 && config.smtp.port < 65536, 'PUBLIC_SMTP_TLS_REQUIRED');
  requireThat(lab ? config.smtp.host === 'mailpit' && config.smtp.port === 1025 : dns(config.smtp.host), 'PUBLIC_SMTP_HOST_INVALID');
  requireThat(!lab || config.smtp.security === 'tls', 'PUBLIC_REHEARSAL_STARTTLS_REQUIRED');
  requireThat(config.smtp.port !== 465 || config.smtp.security === 'ssl', 'PUBLIC_SMTP_PORT_PROTOCOL');
  requireThat(![25,587,2525].includes(config.smtp.port) || config.smtp.security === 'tls', 'PUBLIC_SMTP_PORT_PROTOCOL');
  if (!lab) requireThat(email(config.acmeEmail), 'PUBLIC_ACME_EMAIL_REQUIRED');
  // Credentials are never accepted in the reviewable configuration or generated JSON.
  for (const k of Object.keys(config.smtp)) requireThat(['host','port','security'].includes(k), 'PUBLIC_SMTP_SECRET_NOT_ALLOWED');
  return {lab, hostname:u.hostname};
}

export function caddyfile(config, projectId, {maintenance=false,mcp=false}={}) {
  const {lab,hostname} = validate(config);
  requireThat(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,35}$/.test(projectId) && projectId !== 'console', 'PUBLIC_PROJECT_INVALID');
  return `{
  admin off
  ${lab ? 'auto_https disable_redirects' : `email ${config.acmeEmail}`}
}
http://${hostname} {
  redir https://${hostname}{uri} 308
}
https://${hostname} {
  ${lab ? 'tls /run/secrets/edge.crt /run/secrets/edge.key' : ''}
  header {
    Referrer-Policy "no-referrer"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Strict-Transport-Security "max-age=86400"
    Content-Security-Policy "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; frame-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  }
  ${maintenance ? `handle {
    header Retry-After 60
    header Cache-Control "no-store"
    respond "Maintenance" 503
  }` : `handle /healthz {
    respond "ok" 200
  }
  ${mcpRoutes(mcp)}
  handle /v1/* {
    header Cache-Control "no-store"
    @product header X-Appwrite-Project ${projectId}
    handle @product {
      reverse_proxy appwrite:80
    }
    @file {
      not header X-Appwrite-Project *
      query project=${projectId}
      path /v1/storage/buckets/*
      method GET HEAD
    }
    handle @file {
      reverse_proxy appwrite:80
    }
    respond "Forbidden" 403
  }
  handle {
    root * /srv
    try_files {path} /index.html
    header Cache-Control "no-store"
    file_server
  }`}
}
:8080 {
  respond /healthz "ok" 200
}
`;
}

export function publicCompose(profile,pins,config) {
  const {lab,hostname} = validate(config);
  // Temporary build egress is allowed only behind the persisted upgrade fence.
  requireThat(profile.cloudBlocked === true || hold(profile)?.phase === 'holding', 'PUBLIC_SEALED_PROFILE_REQUIRED');
  requireThat(/^sha256:[a-f0-9]{64}$/.test(profile.product?.webImage), 'PUBLIC_PINNED_WEB_REQUIRED');
  const c = compose(profile,pins), labels = {[OWNER]:profile.project};
  const bind = (source,target) => ({type:'bind',source:'./'+source,target,read_only:true});
  const env = {
    _APP_DOMAIN:hostname,
    _APP_ROUTER_AUTO_CERTIFICATES:'disabled',
    _APP_EMAIL_CERTIFICATES:lab ? 'operator@salmora.test' : config.acmeEmail,
    _APP_SMTP_HOST:config.smtp.host, _APP_SMTP_PORT:String(config.smtp.port), _APP_SMTP_SECURE:config.smtp.security,
    _APP_SYSTEM_EMAIL_NAME:config.sender.name, _APP_SYSTEM_EMAIL_ADDRESS:config.sender.address,
  };
  for (const n of ['appwrite','worker']) {
    c.services[n].environment = {...c.services[n].environment,...env};
    delete c.services[n].environment._APP_SMTP_USERNAME;
    delete c.services[n].environment._APP_SMTP_PASSWORD;
    // Raw values: dollar signs, quotes and # in passwords must not be interpolated.
    c.services[n].env_file=[{path:'./private/smtp.private.env',required:true,format:'raw'}];
    if(lab)c.services[n].volumes.push(bind('secrets/smtp-ca-bundle.crt','/etc/ssl/certs/ca-certificates.crt'));
  }
  c.services.worker.entrypoint=['php','/usr/src/code/app/worker.php',...PUBLIC_WORKERS];
  c.networks['public-ingress'] = {labels};
  c.volumes['public-tls'] = {name:profile.project+'-public-tls',labels};
  c.services['public-edge'] = {
    image:profile.product.webImage,labels,restart:'unless-stopped',read_only:true,mem_limit:'192m',cpus:1,
    networks:{lab:{aliases:[hostname]},'public-ingress':{}},
    volumes:[bind('config/Caddyfile.public','/etc/caddy/Caddyfile'),'public-tls:/data',
      ...(lab ? [bind('secrets/edge.crt','/run/secrets/edge.crt'),bind('secrets/edge.key','/run/secrets/edge.key')] : [])],
    tmpfs:['/config','/tmp'],
    // Rehearsal maps dynamically on loopback. Public files are only prepared, never applied by this module.
    ports:[80,443].map(target=>({target,published:lab?String(profile.publicEdge?.ports?.[target===80?'http':'https']??0):String(target),host_ip:lab?'127.0.0.1':'0.0.0.0',protocol:'tcp'})),
    logging:{driver:'json-file',options:{'max-size':'5m','max-file':'2'}},
    healthcheck:{test:['CMD','wget','-q','--spider','http://127.0.0.1:8080/healthz'],interval:'5s',timeout:'3s',retries:12},
    depends_on:{appwrite:{condition:'service_healthy'}},
  };
  if(lab) {
    c.services.mailpit = {
      image:MAILPIT,labels,restart:'unless-stopped',networks:['private'],read_only:true,tmpfs:['/tmp'],mem_limit:'128m',cpus:1,
      environment:{MP_SMTP_TLS_CERT:'/run/secrets/edge.crt',MP_SMTP_TLS_KEY:'/run/secrets/edge.key',
        MP_SMTP_REQUIRE_STARTTLS:'true',MP_SMTP_AUTH_FILE:'/run/secrets/smtp.auth',MP_MAX_MESSAGES:'50',MP_DISABLE_VERSION_CHECK:'true'},
      volumes:[bind('secrets/edge.crt','/run/secrets/edge.crt'),bind('secrets/edge.key','/run/secrets/edge.key'),bind('secrets/smtp.auth','/run/secrets/smtp.auth')],
      logging:{driver:'none'},
    };
  } else {
    // Only the trusted provider worker needs outbound SMTP. Runtime code, SQL and Temporal stay internal.
    c.networks['mail-egress']={labels};c.services.worker.networks.push('mail-egress');
  }
  return c;
}

export async function prepare(dir,config) {
  const {load,read,write}=await import('./operator.mjs');
  const s=await load(dir),pins=await read(path.join(s.dir,'images.lock.json'));
  const data=publicCompose(s,pins,config),text=caddyfile(config,s.product.projectId,{mcp:Boolean(mcpPolicy(s))});
  await fs.writeFile(path.join(s.dir,'config/Caddyfile.public'),text,{mode:0o600,flag:'wx'});
  await fs.writeFile(path.join(s.dir,'public-compose.json'),JSON.stringify(data,null,2)+'\n',{mode:0o600,flag:'wx'});
  await write(path.join(s.dir,'evidence/public-profile.json'),{version:1,mode:config.mode,origin:config.origin,
    projectId:s.product.projectId,webImage:s.product.webImage,status:'PREPARED_ONLY',releaseEligible:false});
  return {status:'PREPARED_ONLY',mode:config.mode};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const [action,dir,file]=process.argv.slice(2);
  requireThat(action==='prepare'&&file,'PUBLIC_PREPARE_USAGE');
  console.log(JSON.stringify(await prepare(dir,JSON.parse(await fs.readFile(file,'utf8')))));
}
