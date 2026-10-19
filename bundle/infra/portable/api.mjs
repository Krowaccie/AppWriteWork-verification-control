import https from 'node:https';
import {requireThat} from './operator.mjs';
// Loopback qualification only. Certificate verification stays enabled.
export function localApi(endpoint,ca,base={}) {
  requireThat(/^https:\/\/localhost:[1-9][0-9]*\/v1$/.test(endpoint),'PORTABLE_LOCAL_HTTPS_REQUIRED');
  return async (method,route,body,headers={})=>{
    requireThat(route.startsWith('/')&&!route.startsWith('//')&&!route.includes('..'),'PORTABLE_ROUTE_INVALID');
    let bytes,contentType;
    if(body instanceof FormData) {
      const req=new Request('http://unused.invalid',{method:'POST',body});
      bytes=Buffer.from(await req.arrayBuffer());contentType=req.headers.get('content-type');
    }else if(body!==undefined){bytes=Buffer.from(JSON.stringify(body));contentType='application/json';}
    return new Promise((resolve,reject)=>{
      const req=https.request(endpoint+route,{method,ca,timeout:60000,headers:{...base,...headers,...(bytes?{'content-type':contentType,'content-length':bytes.length}:{})}},res=>{
        const chunks=[];res.on('data',x=>chunks.push(x));res.on('end',()=>{
          let value;try{value=JSON.parse(Buffer.concat(chunks).toString());}catch{value=null;}
          if(res.statusCode>=300){
            // Preserve the first causal operation/argument without values, query strings or response bodies.
            const argument=String(value?.message??'').match(/(?:Invalid|Param) [`"']([A-Za-z][A-Za-z0-9_]*)[`"']/)?.[1];
            const e=new Error('PORTABLE_HTTP_'+res.statusCode+'_'+(value?.type||'unknown')+' '+method+' '+route.split('?')[0]+(argument?' argument='+argument:''));
            e.status=res.statusCode;e.method=method;e.route=route.split('?')[0];e.argument=argument;reject(e);
          }
          else resolve({value,status:res.statusCode,fallbackCookies:res.headers['x-fallback-cookies']});
        });res.on('error',reject);
      });req.on('timeout',()=>req.destroy(new Error('PORTABLE_HTTP_TIMEOUT')));req.on('error',reject);
      req.end(bytes);
    });
  };
}
