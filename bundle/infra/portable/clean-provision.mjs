// Only used in a new, plan-owned local installation; no import and no Cloud client.
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {read,write,save,requireThat} from './operator.mjs';
import {credentials} from './product.mjs';
import {localApi} from './api.mjs';

export async function resource({request,route,create,expected}){
  let item;
  try{item=(await request('GET',route)).value;}catch(e){if(e.status!==404)throw e;}
  if(!item){
    try{await create();}catch(e){if(e.status!==409)throw e;}
    item=(await request('GET',route)).value;
  }
  requireThat(expected(item),'CLEAN_RESOURCE_CONFLICT');return item;
}
export async function keyOnce({c,role,scopes,admin,persist}){
  const field=role==='operator'?'apiKey':'workerKey';
  if(c[field])return;
  // An ACK can be lost after server-side creation. Do not issue another POST or rotate.
  requireThat(!c.pendingKey,'CLEAN_KEY_ACK_UNKNOWN');
  c.pendingKey=role;await persist(c);
  const r=(await admin('POST','/projects/'+c.projectId+'/keys',{keyId:'clean-'+role,name:'Clean installation '+role,
    scopes,expire:new Date(Date.now()+7*86400000).toISOString()})).value;
  requireThat(r?.secret&&r.$id,'CLEAN_KEY_ACK_INVALID');
  c[field]=r.secret;c[field+'Id']=r.$id;delete c.pendingKey;await persist(c);
}
export async function provisionClean(s,config){
  requireThat(s.deploymentBinding&&!s.publicEdge,'CLEAN_TARGET_BINDING');
  const {ca,c,admin,close}=await credentials(s),file=path.join(s.dir,'private/appwrite.private.json');
  const persist=x=>write(file,x);
  try{
    requireThat(!c.source&&!c.guestId&&!c.databaseId,'CLEAN_LEGACY_STATE_REJECTED');
    if(!c.cleanBinding){
      requireThat(!c.projectId&&!s.product,'CLEAN_EXISTING_INSTALLATION');
      const suffix=randomBytes(6).toString('hex');
      Object.assign(c,{cleanBinding:s.deploymentBinding,projectId:'portable'+suffix,teamId:'portableteam'+suffix,
        bucketId:'portablebytes'+suffix,ownerId:'owner'+suffix,tenantId:'tenant'+suffix,
        owner:{...config.owner,password:randomBytes(32).toString('hex')}});
      await persist(c); // Identities before their first remote effect, including interrupted creation.
    }
    requireThat(c.cleanBinding===s.deploymentBinding&&c.owner.email===config.owner.email&&c.owner.name===config.owner.name,'CLEAN_IDENTITY_DRIFT');
    await resource({request:admin,route:'/teams/'+c.teamId,
      create:()=>admin('POST','/teams',{teamId:c.teamId,name:'Portable installation'}),expected:v=>v.$id===c.teamId&&v.name==='Portable installation'});
    await resource({request:admin,route:'/projects/'+c.projectId,
      create:()=>admin('POST','/projects',{projectId:c.projectId,teamId:c.teamId,region:'default',name:'Salmora portable'}),
      expected:v=>v.$id===c.projectId&&v.teamId===c.teamId&&v.name==='Salmora portable'});
    for(const [i,hostname] of ['localhost','127.0.0.1','host.docker.internal'].entries()){
      const id='local'+i;
      await resource({request:admin,route:'/projects/'+c.projectId+'/platforms/'+id,
        create:()=>admin('POST','/projects/'+c.projectId+'/platforms',{platformId:id,type:'web',name:'Local Docker',hostname}),
        expected:v=>v.$id===id&&v.type==='web'&&v.hostname===hostname});
    }
    await keyOnce({c,role:'operator',admin,persist,scopes:['users.read','users.write','buckets.read','buckets.write','files.read','files.write',
      'functions.read','functions.write','execution.read','execution.write','databases.read']});
    await keyOnce({c,role:'storage',admin,persist,scopes:['buckets.read','files.read','files.write']});
    const api=localApi(s.endpoint,ca,{'x-appwrite-project':c.projectId,'x-appwrite-key':c.apiKey});
    await resource({request:api,route:'/storage/buckets/'+c.bucketId,
      create:()=>api('POST','/storage/buckets',{bucketId:c.bucketId,name:'Private product bytes',permissions:[],fileSecurity:true,
        enabled:true,maximumFileSize:30000000,allowedFileExtensions:[],compression:'none',encryption:false,antivirus:false}),
      expected:v=>v.$id===c.bucketId&&v.fileSecurity===true&&v.enabled===true&&v.$permissions?.length===0&&v.maximumFileSize===30000000});
    await resource({request:api,route:'/users/'+c.ownerId,
      create:()=>api('POST','/users',{userId:c.ownerId,...c.owner}),
      expected:v=>v.$id===c.ownerId&&v.email===c.owner.email&&v.name===c.owner.name&&v.status===true&&v.labels?.length===0});
    // Authenticate with the original local secret, rather than accepting a matching email.
    const anon=localApi(s.endpoint,ca,{'x-appwrite-project':c.projectId});
    const login=await anon('POST','/account/sessions/email',{email:c.owner.email,password:c.owner.password});
    const account=localApi(s.endpoint,ca,{'x-appwrite-project':c.projectId,'x-fallback-cookies':login.fallbackCookies});
    try{requireThat((await account('GET','/account')).value.$id===c.ownerId,'CLEAN_OWNER_AUTHENTICATION');}
    finally{await account('DELETE','/account/sessions/current');}
    s.product={...s.product,version:1,profile:'salmora-portable-no-key.v1',projectId:c.projectId,deviceFixtureEnabled:false};await save(s);
    return {status:'PROVISIONED',projectId:c.projectId,ownerId:c.ownerId,tenantId:c.tenantId,importedUsers:0};
  }finally{await close();}
}
