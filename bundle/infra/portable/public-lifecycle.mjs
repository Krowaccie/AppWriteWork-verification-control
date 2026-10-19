import fs from 'node:fs/promises';
import path from 'node:path';
import {X509Certificate, createPrivateKey} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {load, save, read, write, requireThat, inventory, docker, stop} from './operator.mjs';
import {validate, caddyfile} from './public-edge.mjs';
import {edgeProfile, deployment} from './deployment.mjs';
import {mcpPolicy} from './mcp-profile.mjs';
import {hold} from './upgrade-contract.mjs';

export function smtpValues(text) {
  const lines=text.replace(/\r?\n$/,'').split(/\r?\n/), values={};
  for (const line of lines) {
    const match=/^(_APP_SMTP_USERNAME|_APP_SMTP_PASSWORD)=([^\r\n\x00]+)$/.exec(line);
    requireThat(match && !Object.hasOwn(values,match[1]), 'PUBLIC_SMTP_ENV_INVALID');
    values[match[1]]=match[2];
  }
  requireThat(Object.keys(values).length===2, 'PUBLIC_SMTP_ENV_INVALID');
  return values;
}
async function regular(s,name,{privateFile=false}={}) {
  const p=path.join(s.dir,name), st=await fs.lstat(p);
  requireThat(st.isFile() && !st.isSymbolicLink(), 'PUBLIC_FILE_INVALID');
  if(privateFile && process.platform!=='win32') requireThat((st.mode&0o077)===0,'PUBLIC_SECRET_FILE_PERMISSIONS');
  return fs.readFile(p,'utf8');
}
export async function validateFiles(s) {
  const e=edgeProfile(s); if(!e) return;
  const {lab,hostname}=validate(e.config);
  const smtp=smtpValues(await regular(s,'private/smtp.private.env',{privateFile:true}));
  if(lab) {
    const cert=new X509Certificate(await regular(s,'secrets/edge.crt'));
    requireThat(cert.checkHost(hostname) && cert.checkHost('mailpit') &&
      Date.parse(cert.validFrom)<=Date.now() && Date.parse(cert.validTo)>Date.now(), 'PUBLIC_CERTIFICATE_INVALID');
    requireThat(cert.checkPrivateKey(createPrivateKey(await regular(s,'secrets/edge.key',{privateFile:true}))), 'PUBLIC_CERTIFICATE_KEY_MISMATCH');
    await regular(s,'secrets/smtp-ca-bundle.crt');
    requireThat((await regular(s,'secrets/smtp.auth',{privateFile:true})).replace(/\r?\n$/,'')===
      smtp._APP_SMTP_USERNAME+':'+smtp._APP_SMTP_PASSWORD, 'PUBLIC_SMTP_AUTH_DRIFT');
  }
  return {status:'VALID',mode:e.config.mode};
}
export async function renderEdge(s) {
  const e=edgeProfile(s); if(!e) return;
  await fs.writeFile(path.join(s.dir,'config/Caddyfile.public'),caddyfile(e.config,s.product.projectId,{maintenance:Boolean(hold(s)),mcp:Boolean(mcpPolicy(s))}),{mode:0o600});
}
async function stopped(s) {
  requireThat(s.quiesced===true && (await inventory(s)).every(x=>!x.State.Running),'PUBLIC_STOP_REQUIRED');
}
export async function configureEdge(s,config) {
  validate(config); requireThat(!s.publicEdge,'PUBLIC_ALREADY_CONFIGURED');
  await stopped(s);
  const next={...s, publicEdge:{version:1,config,state:'held',reason:'configured',ports:{}}};
  // Validate the complete enabled cohort before persisting any profile change.
  deployment({...next,publicEdge:{...next.publicEdge,state:'enabled'}},await read(path.join(s.dir,'images.lock.json')));
  await validateFiles(next);
  s.publicEdge=next.publicEdge; await renderEdge(s); await save(s);
  await write(path.join(s.dir,'evidence/public-lifecycle.json'),{status:'CONFIGURED_HELD',origin:config.origin,mode:config.mode});
  return {status:'CONFIGURED_HELD',origin:config.origin};
}
export async function enableEdge(s,origin) {
  const e=edgeProfile(s);
  requireThat(e && e.config.origin===origin,'PUBLIC_EXACT_ORIGIN_REQUIRED');
  requireThat(!s.restorePending && s.cloudBlocked===true,'PUBLIC_RECOVERY_AND_SEAL_REQUIRED');
  await stopped(s); await validateFiles(s);
  if(s.restoredFrom) requireThat(!(await docker(s,['ps','-q','--filter','label=io.appwritework.portable='+s.restoredFrom])), 'PUBLIC_RESTORE_SOURCE_MUST_BE_OFF');
  s.publicEdge={...e,state:'enabled',reason:undefined}; await save(s);
  return {status:'ENABLED_FOR_NEXT_START',origin};
}
export async function holdEdge(s) {
  requireThat(edgeProfile(s),'PUBLIC_PROFILE_REQUIRED');
  await stop(s); s.publicEdge={...s.publicEdge,state:'held',reason:'operator'}; await save(s);
  return {status:'HELD'};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const [action,dir,arg]=process.argv.slice(2);
  (async()=>{const s=await load(dir);return action==='configure'?configureEdge(s,await read(arg)):
    action==='enable'?enableEdge(s,arg):action==='hold'?holdEdge(s):
    action==='status'?{publicEdge:edgeProfile(s)}:(()=>{throw new Error('PUBLIC_LIFECYCLE_COMMAND');})();
  })().then(r=>console.log(JSON.stringify(r))).catch(e=>{console.error(e.message);process.exitCode=1;});
}
