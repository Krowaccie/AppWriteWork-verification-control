import {
  authenticateTestCloudRuntimeActive,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from '../../../scripts/verification/test-cloud-provider-contract.mjs';

const HUB = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const O = Object;
const F = O.freeze;
const H = O.hasOwn;
const D = O.getOwnPropertyDescriptor;
const P = O.getPrototypeOf;
const A = Reflect.apply;
const K = Reflect.ownKeys;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
const EMPTY = F([]);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const LIMIT = F({ compressed: 16777216, inflated: 67108864, entry: 16777216, selected: 4194304, total: 16777216, entries: 2048 });
const ARG = F({
  qualify: ['runtimeQualification', 'context', 'sourceArtifactSet'],
  consume: ['runtimeQualification', 'context', 'qualification'],
  arm: ['runtimeQualification', 'context', 'qualification', 'providerContractQualification', 'providerSetupReadbackQualification', 'browserScenarioQualification'],
  read: ['runtimeQualification', 'context', 'providerContractQualification', 'providerSetupReadbackQualification', 'browserScenarioQualification', 'policyOrdinal', 'occurrenceIndex'],
  close: ['runtimeQualification', 'context', 'qualification', 'outcome', 'providerContractQualification', 'providerSetupReadbackQualification', 'browserScenarioQualification'],
  begin: ['runtimeQualification', 'context', 'browserArtifactSetHandoff', 'providerContractQualification', 'identityBindingsQualification', 'expectedEnvironmentDigest', 'expectedProviderContractDigest', 'expectedIdentityBindingsDigest'],
  commit: ['runtimeQualification', 'context', 'browserArtifactSetHandoff', 'providerContractQualification', 'identityBindingsQualification', 'providerSetupReadbackQualification', 'browserArtifactSetDigest', 'originFreeArtifactPolicyDigest', 'protectedArtifactPolicyDigest', 'browserRequestPolicyDigest'],
  abort: ['runtimeQualification', 'browserArtifactSetHandoff'],
  claim: ['runtimeQualification', 'context'],
});
const ORIGIN_KEYS = F(['credentialCarrier','exactCount','expectedResponseStatus','lifecyclePhase','memberPath','method','ordinal','profileId','requestClass','requestHeaderBindings','requestOpaqueHeaderRules','resourceType','responseBodyDigest','responseByteLength','responseHeaderBindings','responseMimeEssence','responseOpaqueHeaderRules','role']);
const PROTECTED_KEYS = F(['credentialCarrier','exactCount','expectedResponseStatus','finalUrl','lifecyclePhase','method','ordinal','profileId','requestClass','requestHeaderBindings','requestOpaqueHeaderRules','resourceType','responseBodyDigest','responseByteLength','responseHeaderBindings','responseMimeEssence','responseOpaqueHeaderRules']);
const ENTRY_KEYS = F(['assets','css','dynamicImports','file','imports','isDynamicEntry','isEntry','name','src']);
const OPAQUE = F(['accept','accept-encoding','accept-language','referer','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','upgrade-insecure-requests','user-agent'].map((name) => F({ name, kind: 'opaque-transport', minimumCount: 0, maximumCount: 1 })));
const BLOCKED = F({ status: 'BLOCKED', value: null, diagnostics: F([F({ code: 'TEST_BROWSER_ARTIFACT_SET_MISMATCH', retryable: false, safeMessage: 'The immutable browser artifact set did not match the trusted setup policy.' })]) });

function pass(value) { return F({ status: 'PASS', value: F(value), diagnostics: EMPTY }); }
function exact(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || P(value) !== O.prototype) return false;
  const own = K(value);
  if (own.length !== keys.length || own.some((key) => typeof key !== 'string')) return false;
  const left = [...own].sort(); const right = [...keys].sort();
  for (let i = 0; i < right.length; i += 1) {
    if (left[i] !== right[i]) return false;
    const descriptor = D(value, right[i]);
    if (descriptor === undefined || !H(descriptor, 'value') || descriptor.enumerable !== true) return false;
  }
  return true;
}
function exactPrivate(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || P(value) !== null) return false;
  const own = K(value);
  if (own.length !== keys.length || own.some((key) => typeof key !== 'string')) return false;
  const left = [...own].sort(); const right = [...keys].sort();
  for (let i = 0; i < right.length; i += 1) {
    if (left[i] !== right[i]) return false;
    const descriptor = D(value, right[i]);
    if (descriptor === undefined || !H(descriptor, 'value') || descriptor.enumerable !== true) return false;
  }
  return true;
}
function token() { return F(O.create(null)); }
function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value) || ArrayBuffer.isView(value)) return value;
  seen.add(value);
  for (const key of K(value)) { const descriptor = D(value, key); if (descriptor && H(descriptor, 'value')) deepFreeze(descriptor.value, seen); }
  return F(value);
}
function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isFinite(value)) throw new TypeError(); return JSON.stringify(O.is(value, -0) ? 0 : value); }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = O.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
const SHA_K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function rr(x,n){return (x>>>n)|(x<<(32-n));}
function sha(value, record) {
  let ownedBytes;
  let padded;
  let hash;
  let w;
  try {
    const bytes = typeof value === 'string' ? (ownedBytes = encoder.encode(value)) : value;
    const size = Math.ceil((bytes.byteLength + 9) / 64) * 64;
    padded = new Uint8Array(size);
    padded.set(bytes);
    padded[bytes.byteLength] = 128;
    const view = new DataView(padded.buffer);
    const bits = bytes.byteLength * 8;
    view.setUint32(size-8, Math.floor(bits/0x100000000), false);
    view.setUint32(size-4, bits>>>0, false);
    hash = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    w = new Uint32Array(64);
    if (record) record.hashScratch = [ownedBytes, padded, hash, w].filter((bytesValue) => bytesValue !== undefined);
    for (let off=0; off<size; off+=64) {
      for(let i=0;i<16;i+=1)w[i]=view.getUint32(off+i*4,false);
      for(let i=16;i<64;i+=1){const s0=rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>>3);const s1=rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}
      let [a,b,c,d,e,f,g,h]=hash;
      for(let i=0;i<64;i+=1){const s1=rr(e,6)^rr(e,11)^rr(e,25);const t1=(h+s1+((e&f)^(~e&g))+SHA_K[i]+w[i])>>>0;const s0=rr(a,2)^rr(a,13)^rr(a,22);const t2=(s0+((a&b)^(a&c)^(b&c)))>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
      hash[0]=(hash[0]+a)>>>0;hash[1]=(hash[1]+b)>>>0;hash[2]=(hash[2]+c)>>>0;hash[3]=(hash[3]+d)>>>0;hash[4]=(hash[4]+e)>>>0;hash[5]=(hash[5]+f)>>>0;hash[6]=(hash[6]+g)>>>0;hash[7]=(hash[7]+h)>>>0;
    }
    return 'sha256:' + [...hash].map((word)=>word.toString(16).padStart(8,'0')).join('');
  } finally {
    ownedBytes?.fill(0);
    padded?.fill(0);
    hash?.fill(0);
    w?.fill(0);
    if (record) record.hashScratch = [];
  }
}
function safePath(value){return typeof value==='string'&&value.length>0&&value.length<=512&&!value.startsWith('/')&&!value.endsWith('/')&&!value.includes('\\')&&!value.includes('?')&&!value.includes('#')&&!value.includes('\0')&&!/%2f|%5c/i.test(value)&&value.split('/').every((part)=>part!==''&&part!=='.'&&part!=='..');}
function octal(bytes){const text=decoder.decode(bytes).replace(/[\0 ]+$/u,'');if(!/^[0-7]+$/.test(text))throw new TypeError();const value=Number.parseInt(text,8);if(!Number.isSafeInteger(value)||value<0)throw new TypeError();return value;}
function zeros(bytes){for(const byte of bytes)if(byte!==0)return false;return true;}
function parseTar(bytes){
  if(!(bytes instanceof Uint8Array)||bytes.byteLength>LIMIT.inflated)throw new TypeError();
  const members=new Map();const folded=new Set();let offset=0;let count=0;let end=0;
  while(offset+512<=bytes.byteLength){const header=bytes.subarray(offset,offset+512);offset+=512;if(zeros(header)){end+=1;if(end===2)break;continue;}if(end!==0||++count>LIMIT.entries)throw new TypeError();
    const stored=octal(header.subarray(148,156));let sum=0;for(let i=0;i<512;i+=1)sum+=i>=148&&i<156?32:header[i];if(stored!==sum)throw new TypeError();
    const namePart=decoder.decode(header.subarray(0,100)).replace(/\0.*$/su,'');const prefix=decoder.decode(header.subarray(345,500)).replace(/\0.*$/su,'');const name=prefix===''?namePart:`${prefix}/${namePart}`;
    if(!safePath(name)||folded.has(name.toLowerCase()))throw new TypeError();folded.add(name.toLowerCase());
    const size=octal(header.subarray(124,136));const type=header[156];if(size>LIMIT.entry||offset+size>bytes.byteLength||![0,48,53].includes(type)||(type===53&&size!==0))throw new TypeError();
    if(type!==53)members.set(name,bytes.subarray(offset,offset+size));offset+=Math.ceil(size/512)*512;
  }
  if(end!==2)return (()=>{throw new TypeError();})();return members;
}
function hostedSitePayloadDigest(members,record){const files=[];for(const [path,bytes] of members){if(path==='build-identity.json')continue;files.push({path,mode:'100644',contentDigest:sha(bytes,record)});}files.sort((left,right)=>left.path<right.path?-1:left.path>right.path?1:0);return sha(canonical(files),record);}
function settleWithin(promise) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => finish(false), 5000);
    timer.unref?.();
    promise.then(() => finish(true), () => finish(false));
  });
}
function startStreamCancel(record) {
  if (record.cancelCompletion !== undefined) return record.cancelCompletion;
  if (record.reader === undefined) return Promise.resolve(true);
  try {
    record.cancelCompletion = settleWithin(Promise.resolve(record.reader.cancel()));
  } catch {
    record.cancelCompletion = Promise.resolve(false);
  }
  return record.cancelCompletion;
}
async function gunzip(bytes, record) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader();
  record.reader = reader;
  record.temporaryChunks = [];
  let total = 0;
  let complete = false;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        if (record.abortRequested) throw new TypeError();
        complete = true;
        break;
      }
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) throw new TypeError();
      if (record.abortRequested) {
        chunk.fill(0);
        throw new TypeError();
      }
      if (chunk.byteLength > LIMIT.inflated - total) {
        chunk.fill(0);
        throw new TypeError();
      }
      record.temporaryChunks.push(chunk);
      total += chunk.byteLength;
    }
    const out = new Uint8Array(total);
    record.inflated = out;
    let offset = 0;
    for (const chunk of record.temporaryChunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
      chunk.fill(0);
    }
    record.temporaryChunks = [];
    return out;
  } finally {
    let streamCleanupProven = true;
    if (!complete) streamCleanupProven = await startStreamCancel(record);
    try {
      reader.releaseLock();
    } catch {
      streamCleanupProven = false;
    }
    record.reader = undefined;
    record.cancelCompletion = undefined;
    record.streamCleanupProven = record.streamCleanupProven && streamCleanupProven;
  }
}
function noDuplicateJson(text){
  let i=0;const ws=()=>{while(/\s/.test(text[i]??''))i+=1;};
  const string=()=>{const start=i;i+=1;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i]==='"'){i+=1;return JSON.parse(text.slice(start,i));}if(text.charCodeAt(i)<32)throw new TypeError();i+=1;}throw new TypeError();};
  const value=()=>{ws();if(text[i]==='"'){string();return;}if(text[i]==='{'){i+=1;ws();const keys=new Set();if(text[i]==='}'){i+=1;return;}while(true){ws();if(text[i]!=='"')throw new TypeError();const key=string();if(keys.has(key))throw new TypeError();keys.add(key);ws();if(text[i]!==':')throw new TypeError();i+=1;value();ws();if(text[i]==='}'){i+=1;return;}if(text[i]!==',')throw new TypeError();i+=1;}}if(text[i]==='['){i+=1;ws();if(text[i]===']'){i+=1;return;}while(true){value();ws();if(text[i]===']'){i+=1;return;}if(text[i]!==',')throw new TypeError();i+=1;}}const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));if(!match)throw new TypeError();i+=match[0].length;};
  value();ws();if(i!==text.length)throw new TypeError();
}
function arrayOfStrings(value){return Array.isArray(value)&&value.every((item)=>typeof item==='string');}
function readManifest(members){
  const bytes=members.get('.vite/manifest.json');if(bytes===undefined||bytes.byteLength>1048576)throw new TypeError();const text=decoder.decode(bytes);noDuplicateJson(text);const manifest=JSON.parse(text);
  if(manifest===null||typeof manifest!=='object'||Array.isArray(manifest)||P(manifest)!==O.prototype)throw new TypeError();const keys=new Set(O.keys(manifest));
  for(const key of keys){const entry=manifest[key];if(entry===null||typeof entry!=='object'||Array.isArray(entry)||O.keys(entry).some((name)=>!ENTRY_KEYS.includes(name))||!H(entry,'file')||!safePath(entry.file)||!members.has(entry.file))throw new TypeError();
    for(const name of ['name','src'])if(H(entry,name)&&(typeof entry[name]!=='string'||entry[name]===''))throw new TypeError();for(const name of ['isEntry','isDynamicEntry'])if(H(entry,name)&&typeof entry[name]!=='boolean')throw new TypeError();
    for(const name of ['imports','dynamicImports'])if(H(entry,name)&&(!arrayOfStrings(entry[name])||entry[name].some((item)=>!keys.has(item))))throw new TypeError();for(const name of ['css','assets'])if(H(entry,name)&&(!arrayOfStrings(entry[name])||entry[name].some((item)=>!safePath(item)||!members.has(item))))throw new TypeError();
  }return manifest;
}
function one(values){if(values.length!==1)throw new TypeError();return values[0];}
function viteRoles(manifest){
  const root=manifest['index.html'];if(!root||root.name!=='index'||root.src!=='index.html'||root.isEntry!==true||root.isDynamicEntry===true)throw new TypeError();
  const appKey=one((root.dynamicImports??[]).filter((key)=>manifest[key].name==='App'&&manifest[key].isDynamicEntry===true));const app=manifest[appKey];
  const dashKey=one((app.dynamicImports??[]).filter((key)=>manifest[key].name==='Dashboard'&&manifest[key].isDynamicEntry===true));const dash=manifest[dashKey];
  const selected=new Set();const visit=(key)=>{if(selected.has(key))return;selected.add(key);for(const child of manifest[key].imports??[])visit(child);};visit('index.html');visit(appKey);visit(dashKey);if(selected.size!==15)throw new TypeError();
  const named=(name,predicate=()=>true)=>one([...selected].filter((key)=>manifest[key].name===name&&predicate(manifest[key])));const appwrite=named('appwrite',(entry)=>entry.isDynamicEntry===true);const vendor=one((manifest[appwrite].imports??[]).filter((key)=>selected.has(key)&&manifest[key].name==='appwrite'&&manifest[key].isDynamicEntry!==true));const callout=named('Callout');
  const css=(entry)=>{if(!Array.isArray(entry.css)||entry.css.length!==1)throw new TypeError();return entry.css[0];};
  const roles=[['apiClient-js',manifest[named('apiClient')].file],['App-js',app.file],['App-css',css(app)],['appwrite-js',manifest[appwrite].file],['appwrite-vendor-js',manifest[vendor].file],['Callout-js',manifest[callout].file],['Callout-css',css(manifest[callout])],['Dashboard-js',dash.file],['Dashboard-css',css(dash)],['external-link-js',manifest[named('external-link')].file],['index-js',root.file],['index-css',css(root)],['mcpConnect-js',manifest[named('mcpConnect')].file],['play-js',manifest[named('play')].file],['publicProjectLinks-js',manifest[named('publicProjectLinks')].file],['refresh-js',manifest[named('refresh-cw')].file],['terminal-js',manifest[named('terminal')].file],['useTheme-js',manifest[named('useTheme')].file],['xyflow-js',manifest[named('xyflow')].file]];
  if(roles.length!==19||new Set(roles.map((row)=>row[1])).size!==19)throw new TypeError();for(const key of selected){if((manifest[key].assets??[]).length!==0)throw new TypeError();const allowed=key==='index.html'||key===appKey||key===dashKey||key===callout;if(!allowed&&(manifest[key].css??[]).length!==0)throw new TypeError();}return new Map(roles);
}
const LAYOUT=F([
['index-html','index.html','main-document','APPLICATION_NAVIGATION','document','text/html',1],['App-js','App-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['App-css','App-css','build-asset','APPLICATION_NAVIGATION','stylesheet','text/css',1],['appwrite-js','appwrite-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['appwrite-vendor-js','appwrite-vendor-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['Callout-js','Callout-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['Callout-css','Callout-css','build-asset','APPLICATION_NAVIGATION','stylesheet','text/css',1],['index-js','index-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['index-css','index-css','build-asset','APPLICATION_NAVIGATION','stylesheet','text/css',1],['terminal-js','terminal-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['xyflow-js','xyflow-js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['theme-init-js','theme-init.js','build-asset','APPLICATION_NAVIGATION','script','text/javascript',1],['salmora-mark','salmora-mark.svg','build-asset','APPLICATION_NAVIGATION','image','image/svg+xml',1],['apiClient-js','apiClient-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['Dashboard-js','Dashboard-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['Dashboard-css','Dashboard-css','build-asset','OWNER_LOGIN','stylesheet','text/css',1],['external-link-js','external-link-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['mcpConnect-js','mcpConnect-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['play-js','play-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['publicProjectLinks-js','publicProjectLinks-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['refresh-js','refresh-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['useTheme-js','useTheme-js','build-asset','OWNER_LOGIN','script','text/javascript',1],['catalog-bundle','catalog/catalog-bundle.json','build-asset','APPLICATION_READ','fetch','application/json',3],['templates-registry','templates/registry.json','build-asset','APPLICATION_READ','fetch','application/json',1],['templates-entitlements','templates/entitlements.json','build-asset','APPLICATION_READ','fetch','application/json',1]]);
function buildRows(members,roles,record){let total=0;const records=[];record.records=records;const rows=LAYOUT.map((layout,ordinal)=>{const [role,source,requestClass,lifecyclePhase,resourceType,mime,exactCount]=layout;const memberPath=roles.get(source)??source;const bytes=members.get(memberPath);if(!bytes||bytes.byteLength<1||bytes.byteLength>LIMIT.selected||bytes.byteLength>LIMIT.total-total||(total+=bytes.byteLength)>LIMIT.total)throw new TypeError();const retained=Buffer.from(bytes);const memberRecord={bytes:retained,digest:undefined,length:retained.byteLength};records.push(memberRecord);const digest=sha(retained,record);memberRecord.digest=digest;return deepFreeze({credentialCarrier:'none',exactCount,expectedResponseStatus:200,lifecyclePhase,memberPath,method:'GET',ordinal,profileId:'synthetic-immutable-asset',requestClass,requestHeaderBindings:EMPTY,requestOpaqueHeaderRules:OPAQUE,resourceType,responseBodyDigest:digest,responseByteLength:retained.byteLength,responseHeaderBindings:EMPTY,responseMimeEssence:mime,responseOpaqueHeaderRules:EMPTY,role});});if(rows.length!==25||rows.reduce((sum,row)=>sum+row.exactCount,0)!==27||rows.some((row)=>!exact(row,ORIGIN_KEYS)))throw new TypeError();return {rows:F(rows),records};}
function siteFrom(source,record){const descriptor=D(source,'releaseEligibleArtifacts');if(!descriptor||!H(descriptor,'value')||!Array.isArray(descriptor.value))throw new TypeError();const matches=descriptor.value.filter((item)=>item&&typeof item==='object'&&item.kind==='site'&&item.logicalTarget==='web'&&item.relativePath==='site/site.tar.gz');if(matches.length!==1)throw new TypeError();const site=matches[0];if(!(site.bytes instanceof Uint8Array)||site.bytes.byteLength<1||site.bytes.byteLength>LIMIT.compressed||site.sizeBytes!==site.bytes.byteLength||!DIGEST.test(site.transportDigest)||sha(site.bytes,record)!==site.transportDigest)throw new TypeError();return site;}
const qRecords=new WeakMap();const hRecords=new WeakMap();let current;
function zeroOwnedBytes(record, includeRetained) {
  let ok = true;
  const fill = (bytes) => {
    try {
      bytes?.fill(0);
    } catch {
      ok = false;
    }
  };
  for (const chunk of record.temporaryChunks??[]) fill(chunk);
  record.temporaryChunks = [];
  for (const scratch of record.hashScratch??[]) fill(scratch);
  record.hashScratch = [];
  fill(record.inflated);
  record.inflated = undefined;
  if (record.members instanceof Map) {
    for (const bytes of record.members.values()) fill(bytes);
    record.members.clear();
  }
  record.members = undefined;
  if (includeRetained) {
    for (const member of record.records??[]) fill(member.bytes);
    record.records = [];
  }
  return ok;
}
function dropAuthorityReferences(record) {
  record.runtimeQualification = undefined;
  record.context = undefined;
  record.qualification = null;
  record.provider = undefined;
  record.identity = undefined;
  record.setup = undefined;
  record.scenario = undefined;
  record.environmentDigest = undefined;
  record.providerDigest = undefined;
  record.identityDigest = undefined;
  record.protectedDigest = undefined;
  record.policyDigest = undefined;
  record.artifactDigest = undefined;
  record.originDigest = undefined;
  record.rows = undefined;
  record.next = undefined;
}
function installTombstone(record, state, cleanupProven) {
  const tombstone = F({ tombstone: true, qualification: null, state, cleanupProven });
  if (current === record || current?.tombstone === true) current = tombstone;
}
function resolveRecordCleanup(record, cleanupProven) {
  if (record.cleanupResolved) return;
  record.cleanupResolved = true;
  const resolve = record.resolveCleanup;
  record.resolveCleanup = undefined;
  resolve(F({ cleanupProven }));
}
function finishOwnerTemporaryCleanup(record) {
  const cleanupProven = zeroOwnedBytes(record, false) && record.streamCleanupProven;
  record.ownerActive = false;
  resolveRecordCleanup(record, cleanupProven);
  return cleanupProven;
}
function finishOwnerAbort(record, state = 'BLOCKED_ABORTED') {
  installTombstone(record, state, false);
  const cleanupProven = zeroOwnedBytes(record, true) && record.streamCleanupProven;
  record.ownerActive = false;
  record.cleanup = true;
  record.cleanupProven = cleanupProven;
  record.state = cleanupProven ? state : 'BLOCKED_CLEANUP_UNPROVEN';
  dropAuthorityReferences(record);
  installTombstone(record, record.state, cleanupProven);
  resolveRecordCleanup(record, cleanupProven);
  return cleanupProven;
}
function requestAbort(record, state = 'BLOCKED_ABORTED') {
  if (!record) return true;
  if (record.tombstone === true) return record.cleanupProven;
  if (record.cleanup === true) return record.cleanupProven;
  record.abortRequested = true;
  record.state = 'ABORT_REQUESTED';
  installTombstone(record, state, false);
  if (record.ownerActive) {
    startStreamCancel(record);
    zeroOwnedBytes(record, true);
    dropAuthorityReferences(record);
    return false;
  }
  const cleanupProven = zeroOwnedBytes(record, true) && record.streamCleanupProven;
  record.cleanup = true;
  record.cleanupProven = cleanupProven;
  record.state = cleanupProven ? state : 'BLOCKED_CLEANUP_UNPROVEN';
  dropAuthorityReferences(record);
  installTombstone(record, record.state, cleanupProven);
  return cleanupProven;
}
function wipe(record){return requestAbort(record);}
function block(record=current){if(record?.tombstone!==true)requestAbort(record);return BLOCKED;}
function active(runtimeQualification){return readTestCloudRuntimeLifecycle()==='ACTIVE'&&authenticateTestCloudRuntimeActive(Object.freeze({runtimeQualification}))===true;}
function tuple(record,runtimeQualification,context){return O.is(record.runtimeQualification,runtimeQualification)&&O.is(record.context,context);}
const bridgeReceiver=F(O.create(null));let registrationState='EMPTY';let regObject;let dispatchReceiver;let authProvider;let authScenario;let policyReader;
function terminallyBlockRegistration() {
  registrationState = 'BLOCKED';
  regObject = undefined;
  dispatchReceiver = undefined;
  authProvider = undefined;
  authScenario = undefined;
  policyReader = undefined;
  readTestCloudRuntimeLifecycle(BLOCKED);
  return false;
}
function hub(){const descriptor=D(globalThis,HUB);return descriptor&&H(descriptor,'value')&&descriptor.enumerable===false&&descriptor.configurable===true&&descriptor.writable===false?descriptor.value:undefined;}
function hubFunction(value,name){const descriptor=D(value,name);return descriptor&&H(descriptor,'value')&&typeof descriptor.value==='function'&&descriptor.enumerable===true&&descriptor.configurable===false&&descriptor.writable===false?descriptor.value:undefined;}
function hubReceiver(value){const descriptor=D(value,'bridgeReceiver');return descriptor&&H(descriptor,'value')&&descriptor.enumerable===true&&descriptor.configurable===false&&descriptor.writable===false?descriptor.value:undefined;}
function call(fn,args){return A(fn,dispatchReceiver,[args]);}
function consumeCurrentBrowserArtifactSetHandoff(args){try{if(!O.is(this,bridgeReceiver)||!exact(args,ARG.claim)||!active(args.runtimeQualification))return false;const record=current;if(!record||record.state!=='QUALIFIED'||!tuple(record,args.runtimeQualification,args.context))return false;record.state='HANDOFF_RESERVING';const browserArtifactSetHandoff=token();hRecords.set(browserArtifactSetHandoff,{record,state:'UNUSED'});record.state='HANDOFF_READY';return F({browserArtifactSetDigest:record.artifactDigest,browserArtifactSetHandoff});}catch{block();return false;}}
function beginBrowserArtifactSetSetupBinding(args){try{if(!O.is(this,bridgeReceiver)||!exact(args,ARG.begin)||!active(args.runtimeQualification))return false;const handoff=hRecords.get(args.browserArtifactSetHandoff);const record=current;if(!handoff||handoff.record!==record||handoff.state!=='UNUSED'||record.state!=='HANDOFF_READY'||!tuple(record,args.runtimeQualification,args.context)||args.providerContractQualification===null||args.identityBindingsQualification===null||![args.expectedEnvironmentDigest,args.expectedProviderContractDigest,args.expectedIdentityBindingsDigest].every((digest)=>DIGEST.test(digest)))return false;handoff.state='CONSUMED';record.state='SETUP_BINDING';record.provider=args.providerContractQualification;record.identity=args.identityBindingsQualification;record.environmentDigest=args.expectedEnvironmentDigest;record.providerDigest=args.expectedProviderContractDigest;record.identityDigest=args.expectedIdentityBindingsDigest;return F({browserArtifactSetDigest:record.artifactDigest,originFreeArtifactPolicyDigest:record.originDigest,originFreeArtifactPolicyRows:deepFreeze(record.rows.map((row)=>deepFreeze({...row})))});}catch{block();return false;}}
function commitBrowserArtifactSetSetupBinding(args){try{if(!O.is(this,bridgeReceiver)||!exact(args,ARG.commit)||!active(args.runtimeQualification))return false;const handoff=hRecords.get(args.browserArtifactSetHandoff);const record=current;const digests=[args.browserArtifactSetDigest,args.originFreeArtifactPolicyDigest,args.protectedArtifactPolicyDigest,args.browserRequestPolicyDigest];if(!handoff||handoff.record!==record||handoff.state!=='CONSUMED'||record.state!=='SETUP_BINDING'||!tuple(record,args.runtimeQualification,args.context)||!O.is(record.provider,args.providerContractQualification)||!O.is(record.identity,args.identityBindingsQualification)||args.providerSetupReadbackQualification===null||args.browserArtifactSetDigest!==record.artifactDigest||args.originFreeArtifactPolicyDigest!==record.originDigest||!digests.every((digest)=>DIGEST.test(digest))||new Set(digests).size!==4)return false;record.setup=args.providerSetupReadbackQualification;record.protectedDigest=args.protectedArtifactPolicyDigest;record.policyDigest=args.browserRequestPolicyDigest;record.state='SETUP_BOUND';return true;}catch{block();return false;}}
function abortBrowserArtifactSetSetupBinding(args){try{if(!O.is(this,bridgeReceiver)||!exact(args,ARG.abort))return false;const handoff=hRecords.get(args.browserArtifactSetHandoff);if(!handoff||!O.is(handoff.record.runtimeQualification,args.runtimeQualification))return false;if(handoff.state==='ABORTED')return true;const ok=wipe(handoff.record);handoff.state=ok?'ABORTED':'BLOCKED';return ok;}catch{return false;}}
function registration(){if(regObject)return regObject;const value=O.create(null);O.defineProperties(value,{receiver:{value:bridgeReceiver,enumerable:true,configurable:false,writable:false},consumeCurrentBrowserArtifactSetHandoff:{value:consumeCurrentBrowserArtifactSetHandoff,enumerable:true,configurable:false,writable:false},beginBrowserArtifactSetSetupBinding:{value:beginBrowserArtifactSetSetupBinding,enumerable:true,configurable:false,writable:false},commitBrowserArtifactSetSetupBinding:{value:commitBrowserArtifactSetSetupBinding,enumerable:true,configurable:false,writable:false},abortBrowserArtifactSetSetupBinding:{value:abortBrowserArtifactSetSetupBinding,enumerable:true,configurable:false,writable:false}});regObject=F(value);return regObject;}
function protectedMatches(origin,row){if(!exactPrivate(row,PROTECTED_KEYS))return false;let url;try{url=new URL(row.finalUrl);}catch{return false;}if(url.protocol!=='https:'||url.username!==''||url.password!==''||url.search!==''||url.hash!==''||url.pathname!==`/${origin.memberPath}`)return false;for(const key of PROTECTED_KEYS)if(key!=='finalUrl'&&canonical(row[key])!==canonical(origin[key]))return false;return true;}
function authenticateCurrent(record,scenario,operation,policyOrdinal,occurrenceIndex){if(!active(record.runtimeQualification))return false;if(call(authProvider,{runtimeQualification:record.runtimeQualification,context:record.context,providerContractQualification:record.provider,expectedEnvironmentDigest:record.environmentDigest,expectedProviderContractDigest:record.providerDigest})!==true)return false;const policyArgs=F(O.assign(O.create(null),{runtimeQualification:record.runtimeQualification,context:record.context,providerContractQualification:record.provider,providerSetupReadbackQualification:record.setup}));const result=call(policyReader,policyArgs);const policy=result?.browserRequestPolicy;if(!exactPrivate(policy,['schemaVersion','timeoutMilliseconds','rows','digest'])||policy.schemaVersion!=='test-cloud.browser-request-policy.v1'||policy.timeoutMilliseconds!==5000||!Array.isArray(policy.rows)||policy.rows.length<25||policy.digest!==record.policyDigest)return false;const without={schemaVersion:policy.schemaVersion,timeoutMilliseconds:policy.timeoutMilliseconds,rows:policy.rows};if(sha(canonical(without),record)!==record.policyDigest)return false;const rows=policy.rows.slice(0,25);if(sha(canonical(rows),record)!==record.protectedDigest||rows.some((row,index)=>!protectedMatches(record.rows[index],row)))return false;return call(authScenario,{runtimeQualification:record.runtimeQualification,context:record.context,browserScenarioQualification:scenario,operation,policyOrdinal,occurrenceIndex})===true;}

export async function projectTestCloudBrowserArtifactPolicyRows(args) {
  const record = {
    abortRequested: false,
    streamCleanupProven: true,
    temporaryChunks: [],
    records: [],
    hashScratch: [],
  };
  try {
    if (!exact(args, ['sourceArtifactSet'])) return BLOCKED;
    const site = siteFrom(args.sourceArtifactSet, record);
    const inflated = await gunzip(site.bytes, record);
    if (!DIGEST.test(site.canonicalContentDigest)) return BLOCKED;
    const members = parseTar(inflated);
    if (hostedSitePayloadDigest(members, record) !== site.canonicalContentDigest) return BLOCKED;
    record.members = members;
    const built = buildRows(members, viteRoles(readManifest(members)), record);
    const rows = deepFreeze(built.rows.map((row) => deepFreeze({
      ...row,
      requestHeaderBindings: row.requestHeaderBindings.map((entry) => ({ ...entry })),
      requestOpaqueHeaderRules: row.requestOpaqueHeaderRules.map((entry) => ({ ...entry })),
      responseHeaderBindings: row.responseHeaderBindings.map((entry) => ({ ...entry })),
      responseOpaqueHeaderRules: row.responseOpaqueHeaderRules.map((entry) => ({ ...entry })),
    })));
    const originFreeArtifactPolicyDigest = sha(canonical(rows), record);
    const browserArtifactSetDigest = sha(canonical(rows.map((row) => ({
      ordinal: row.ordinal,
      memberPath: row.memberPath,
      responseBodyDigest: row.responseBodyDigest,
      responseByteLength: row.responseByteLength,
      exactCount: row.exactCount,
    }))), record);
    return pass({
      browserArtifactSetDigest,
      originFreeArtifactPolicyDigest,
      originFreeArtifactPolicyRows: rows,
    });
  } catch {
    return BLOCKED;
  } finally {
    zeroOwnedBytes(record, true);
  }
}

export async function qualifyTestCloudBrowserArtifactSet(args) {
  let record;
  try {
    if (!exact(args, ARG.qualify) || !active(args.runtimeQualification)) return block();
    if (current !== undefined) {
      const duplicate = current;
      if (duplicate.tombstone !== true) {
        const cleanupBarrier = duplicate.cleanupBarrier;
        requestAbort(duplicate);
        if (cleanupBarrier) await cleanupBarrier;
      }
      return BLOCKED;
    }
    let resolveCleanup;
    const cleanupBarrier = new Promise((resolve) => { resolveCleanup = resolve; });
    record = {
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      state: 'BUILD_RESERVED',
      cleanup: false,
      cleanupBarrier,
      resolveCleanup,
      cleanupResolved: false,
      ownerActive: true,
      abortRequested: false,
      streamCleanupProven: true,
      records: [],
      temporaryChunks: [],
    };
    current = record;
    record.state = 'MATERIALIZING';
    const site = siteFrom(args.sourceArtifactSet, record);
    const inflated = await gunzip(site.bytes, record);
    if (record.abortRequested || current !== record || record.state !== 'MATERIALIZING' || !DIGEST.test(site.canonicalContentDigest)) throw new TypeError();
    const members = parseTar(inflated);
    if (hostedSitePayloadDigest(members, record) !== site.canonicalContentDigest) throw new TypeError();
    record.members = members;
    const manifest = readManifest(members);
    const built = buildRows(members, viteRoles(manifest), record);
    record.state = 'ROOT_CLEANUP';
    record.rows = built.rows;
    record.originDigest = sha(canonical(record.rows), record);
    record.artifactDigest = sha(canonical(record.rows.map((row) => ({ ordinal: row.ordinal, memberPath: row.memberPath, responseBodyDigest: row.responseBodyDigest, responseByteLength: row.responseByteLength, exactCount: row.exactCount }))), record);
    if (!finishOwnerTemporaryCleanup(record) || current !== record || record.state !== 'ROOT_CLEANUP') return block(record);
    const qualification = token();
    record.qualification = qualification;
    qRecords.set(qualification, record);
    record.state = 'QUALIFIED';
    return pass({ browserArtifactSetDigest: record.artifactDigest, qualification });
  } catch {
    if (record) {
      if (record.ownerActive) finishOwnerAbort(record);
      else requestAbort(record);
    }
    return BLOCKED;
  }
}

export function consumeQualifiedTestCloudBrowserArtifactSet(args) {
  try {
    if (!exact(args, ARG.consume) || !active(args.runtimeQualification)) return block();
    const record = qRecords.get(args.qualification);
    if (!record || record !== current || record.state !== 'QUALIFIED' || !tuple(record, args.runtimeQualification, args.context)) return block(record);
    record.state = 'HANDOFF_RESERVING';
    const browserArtifactSetHandoff = token();
    hRecords.set(browserArtifactSetHandoff, { record, state: 'UNUSED' });
    record.state = 'HANDOFF_READY';
    return pass({ browserArtifactSetDigest: record.artifactDigest, browserArtifactSetHandoff });
  } catch {
    return block();
  }
}

export function armQualifiedTestCloudBrowserArtifactMembers(args) {
  try {
    if (!exact(args, ARG.arm) || args.browserScenarioQualification === null) return block();
    const record = qRecords.get(args.qualification);
    if (!record || record !== current || !tuple(record, args.runtimeQualification, args.context) || !O.is(record.provider, args.providerContractQualification) || !O.is(record.setup, args.providerSetupReadbackQualification)) return block(record);
    if (!authenticateCurrent(record, args.browserScenarioQualification, 'arm', null, null)) return block(record);
    if (record.state !== 'SETUP_BOUND') return block(record);
    record.state = 'ARMING';
    record.scenario = args.browserScenarioQualification;
    record.next = new Uint16Array(25);
    record.issued = 0;
    record.state = 'ARMED';
    return pass({ armed: true });
  } catch {
    return block();
  }
}

export function readQualifiedTestCloudBrowserArtifactMember(args) {
  try {
    if (!(exact(args, ARG.read) || exactPrivate(args, ARG.read)) || !Number.isSafeInteger(args.policyOrdinal) || args.policyOrdinal < 0 || args.policyOrdinal >= 25 || !Number.isSafeInteger(args.occurrenceIndex) || args.occurrenceIndex < 0) return block();
    const record = current;
    if (!record || !tuple(record, args.runtimeQualification, args.context) || !O.is(record.provider, args.providerContractQualification) || !O.is(record.setup, args.providerSetupReadbackQualification) || !O.is(record.scenario, args.browserScenarioQualification)) return block(record);
    if (!authenticateCurrent(record, args.browserScenarioQualification, 'read', args.policyOrdinal, args.occurrenceIndex)) return block(record);
    if (!['ARMED', 'SERVING'].includes(record.state)) return block(record);
    const row = record.rows[args.policyOrdinal];
    const member = record.records[args.policyOrdinal];
    if (args.occurrenceIndex !== record.next[args.policyOrdinal] || args.occurrenceIndex >= row.exactCount || record.issued >= 27) return block(record);
    const bodyBase64 = A(member.bytes.toString, member.bytes, ['base64']);
    if (bodyBase64.length !== 4 * Math.ceil(member.length / 3) || sha(member.bytes, record) !== member.digest) return block(record);
    record.next[args.policyOrdinal] += 1;
    record.issued += 1;
    record.state = record.issued === 27 ? 'EXHAUSTED' : 'SERVING';
    return pass({ bodyBase64, responseBodyDigest: member.digest, responseByteLength: member.length });
  } catch {
    return block();
  }
}
export async function closeQualifiedTestCloudBrowserArtifactMembers(args) {
  try {
    if (!exact(args, ARG.close) || (args.outcome !== 'abort' && args.outcome !== 'complete')) return BLOCKED;
    const record = current;
    if (args.outcome === 'abort') {
      const qualificationMatches = args.qualification === null ? record?.qualification === undefined : O.is(record?.qualification, args.qualification);
      const downstream = [args.providerContractQualification, args.providerSetupReadbackQualification, args.browserScenarioQualification];
      const allNull = downstream.every((value) => value === null);
      const allExact = record !== undefined && O.is(record.provider, downstream[0]) && O.is(record.setup, downstream[1]) && O.is(record.scenario, downstream[2]);
      if (!record || record.tombstone === true || !tuple(record, args.runtimeQualification, args.context) || !qualificationMatches || (!allNull && !allExact)) return block(record);
      const ownerActive = record.ownerActive;
      const cleanupBarrier = record.cleanupBarrier;
      const immediateCleanup = requestAbort(record, 'CLOSED');
      const cleanupResult = cleanupBarrier ? await cleanupBarrier : F({ cleanupProven: immediateCleanup });
      if (!cleanupResult.cleanupProven || (!ownerActive && !immediateCleanup)) return BLOCKED;
      return pass({ closed: true });
    }
    if (!record || record.tombstone === true || !tuple(record, args.runtimeQualification, args.context) || !O.is(record.qualification, args.qualification) || !O.is(record.provider, args.providerContractQualification) || !O.is(record.setup, args.providerSetupReadbackQualification) || !O.is(record.scenario, args.browserScenarioQualification)) return block(record);
    if (!authenticateCurrent(record, args.browserScenarioQualification, 'complete', null, null) || record.state !== 'EXHAUSTED') return block(record);
    record.state = 'CLOSING';
    const cleanupBarrier = record.cleanupBarrier;
    const immediateCleanup = requestAbort(record, 'CLOSED');
    const cleanupResult = cleanupBarrier ? await cleanupBarrier : F({ cleanupProven: immediateCleanup });
    if (!immediateCleanup || !cleanupResult.cleanupProven) return BLOCKED;
    return pass({ closed: true });
  } catch {
    return block();
  }
}

export function registerTestCloudBrowserArtifactSetBootstrap() {
  try {
    if (registrationState !== 'EMPTY') return terminallyBlockRegistration();
    const shared = hub();
    if (!shared || !isAuthenticTestCloudBootstrapHub(shared) || readTestCloudRuntimeLifecycle() !== 'BOOTSTRAPPING') return terminallyBlockRegistration();
    const receiver = hubReceiver(shared);
    const register = hubFunction(shared, 'registerBrowserArtifactSetSetupBridge');
    if (receiver === undefined || register === undefined) return terminallyBlockRegistration();
    const provider = hubFunction(shared, 'authenticateProviderQualification');
    const scenario = hubFunction(shared, 'authenticateBrowserScenarioQualification');
    const readPolicy = hubFunction(shared, 'readBrowserRequestPolicy');
    const result = A(register, receiver, [registration()]);
    if (provider === undefined || scenario === undefined || readPolicy === undefined || result !== true || readTestCloudRuntimeLifecycle() !== 'BOOTSTRAPPING') return terminallyBlockRegistration();
    dispatchReceiver = receiver;
    authProvider = provider;
    authScenario = scenario;
    policyReader = readPolicy;
    registrationState = 'REGISTERED';
    return true;
  } catch {
    return terminallyBlockRegistration();
  }
}
