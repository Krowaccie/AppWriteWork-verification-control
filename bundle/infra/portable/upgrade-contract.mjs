// Idle-only application upgrade. An interrupted operation remains held.
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
export const sha=b=>createHash('sha256').update(b).digest('hex');
export const requireThat=(v,c)=>{if(!v)throw new Error(c);};
export const PHASES=['hold','checkpoint','build-maintenance','functions','images','seal','verify-held','open','verify'];
export function hold(s){
  if(s.upgradeHold===undefined)return null;
  const h=s.upgradeHold;
  requireThat(h?.version===1&&/^[a-f0-9]{64}$/.test(h.binding)&&['holding','verified'].includes(h.phase),'UPGRADE_HOLD_INVALID');
  requireThat(!s.publicEdge||(s.publicEdge.version===1&&(s.publicEdge.state==='enabled'||
    (s.publicEdge.state==='held'&&s.publicEdge.reason==='restore'&&typeof s.restoredFrom==='string'))),'UPGRADE_PUBLIC_NOT_ENABLED');return h;
}
export function workerAllowed(s,binding){
  const h=hold(s);
  requireThat(!h||(h.phase==='verified'&&binding===h.binding),'UPGRADE_WORKER_HELD');
}
export function validateJournal(j,binding){
  requireThat(j?.version===1&&j.planSha256===binding&&Array.isArray(j.completed)&&
    j.completed.length<=PHASES.length&&j.completed.every((v,i)=>v===PHASES[i])&&
    (j.running===null||j.running===PHASES[j.completed.length]),'UPGRADE_JOURNAL_INVALID');
  requireThat(typeof j.writesMayHaveOpened==='boolean'&&
    (j.writesMayHaveOpened===(j.completed.includes('open')||j.running==='open'||j.running==='verify')),'UPGRADE_JOURNAL_INVALID');return j;
}
export async function phases({journal,binding,persist,execute,through='verify',resume=false,before=async()=>{}}){
  validateJournal(journal,binding);requireThat(PHASES.includes(through),'UPGRADE_PHASE');
  requireThat(!journal.running||resume,'UPGRADE_RESUME_REQUIRED');
  const results={};
  for(let i=journal.completed.length;i<=PHASES.indexOf(through);i++){
    const phase=PHASES[i];await before(phase);
    journal.running=phase;
    if(phase==='open')journal.writesMayHaveOpened=true; // before the first possible new write
    await persist(journal);
    results[phase]=await execute(phase);
    journal.completed.push(phase);journal.running=null;await persist(journal);
  }
  return results;
}
export function holdCompose(c,s){
  if(!hold(s))return c;
  const gateway=c.services.gateway;
  gateway.volumes=gateway.volumes.map(v=>v.target==='/etc/caddy/Caddyfile'?{...v,source:'./private/upgrade.Caddyfile'}:v);
  gateway.env_file=[{path:'./private/upgrade.private.env',required:true,format:'raw'}];
  // A verified cohort may be started explicitly by open(). Its restart policy
  // must already be final when the profile hold is removed, without a second
  // worker recreation after admission reopens.
  if(hold(s).phase==='holding')c.services['execution-worker'].restart='no';
  return c;
}
export async function validateHoldFiles(s){
  if(!hold(s))return;
  const c=JSON.parse(await fs.readFile(path.join(s.dir,'private/appwrite.private.json'),'utf8'));
  requireThat(typeof c.apiKey==='string'&&/^[a-zA-Z0-9._-]{32,}$/.test(c.apiKey)&&
    /^[a-zA-Z0-9_-]{1,36}$/.test(c.projectId)&&c.projectId===s.product?.projectId,'UPGRADE_HOLD_CREDENTIAL');
  const env='SALMORA_UPGRADE_API_KEY='+c.apiKey+'\nSALMORA_UPGRADE_PROJECT='+c.projectId+'\n';
  requireThat(await fs.readFile(path.join(s.dir,'private/upgrade.private.env'),'utf8')===env&&
    await fs.readFile(path.join(s.dir,'private/upgrade.Caddyfile'),'utf8')===GATEWAY,'UPGRADE_HOLD_FILES_CHANGED');
}
export const GATEWAY=`{
  admin off
  auto_https off
}
:443 {
  tls /run/secrets/server.crt /run/secrets/server.key
  @operator {
    header X-Appwrite-Key {$SALMORA_UPGRADE_API_KEY}
    header X-Appwrite-Project {$SALMORA_UPGRADE_PROJECT}
  }
  handle @operator {
    handle /v1/* {
      reverse_proxy appwrite:80
    }
    handle /local-build-identity.json {
      root * /srv
      file_server
    }
    respond 403
  }
  handle {
    header Retry-After 60
    respond "Maintenance" 503
  }
}
:8080 {
  respond /healthz "ok" 200
}
`;
