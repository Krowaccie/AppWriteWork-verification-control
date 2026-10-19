// Explicit reproducible source cohort. Never archive workspace caches or .env files.
import fs from 'node:fs/promises';
import path from 'node:path';
import {sha,requireThat} from './operator.mjs';
export const SOURCE_ROOTS=['infra/portable','apps/local-runtime','apps/mcp-bridge','apps/web','packages/backend-core-py/src','packages/catalog',
 'packages/contracts','packages/local-runtime-protocol','services/local-device-api','services/execution-worker-py','services/appwrite-functions',
 'tools/build','platform/appwrite/desired-state','dev/tests/fixtures','dev/labs/migration-m9','dev/labs/hosting-m8','dev/labs/backup-b2',
 'dev/labs/appwrite-r0','dev/labs/postgres-s0','dev/labs/postgres-s1','dev/labs/postgres-s2','dev/labs/postgres-m1','dev/labs/postgres-m2','dev/labs/temporal-m3','package.json','package-lock.json'];
export async function sourceFiles(root,roots=SOURCE_ROOTS){
 const files={};
 async function visit(relative){
  const p=path.join(root,relative),st=await fs.lstat(p);
  requireThat(!st.isSymbolicLink(),'PORTABLE_SOURCE_SYMLINK');
  if(st.isDirectory()){
   for(const n of (await fs.readdir(p)).sort()){
    if(n.startsWith('.')||['node_modules','__pycache__','dist'].includes(n))continue;
    await visit(relative+'/'+n);
   }
  }else if(st.isFile()){
   requireThat(!/\.private\.|\.env$|\.pem$|\.key$/.test(relative),'PORTABLE_SOURCE_SECRET_PATH');
   files[relative]=sha(await fs.readFile(p));
  }
 }
 for(const r of roots)await visit(r);
 return files;
}
