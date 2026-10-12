// Explicit one-shot operator action immediately before subscription, never a daemon.
import {pathToFileURL} from 'node:url';
import {setTimeout as sleep} from 'node:timers/promises';
import {safeRequest} from './security.mjs';
export function healthURL(raw) {
  const u=new URL(raw);
  if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash||u.pathname!=='/'||!/^[-a-z0-9]+\.onrender\.com$/.test(u.hostname))throw Error('use the verified Render service origin');
  return new URL('/healthz',u);
}
export async function prewarm(raw,{transport=safeRequest,now=Date.now,wait=sleep}={}) {
  const url=healthURL(raw),deadline=now()+120000;
  while(now()<deadline){
    try{
      const r=await transport(url.href,{method:'GET',hosts:[url.hostname],limit:4096,timeoutMs:Math.min(30000,Math.max(1,deadline-now()))});
      const result=JSON.parse(r.body.toString());
      if(r.status===200&&result.ok===true&&result.service==='callback-only')return;
    }catch{}
    if(now()<deadline)await wait(Math.min(3000,deadline-now()));
  }
  throw Error('callback service did not become healthy; subscription must remain unaccepted');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{await prewarm(process.argv[2]);process.stdout.write('Callback process is awake. Signed MCP verification is still required.\n');}
  catch{process.stderr.write('Prewarm failed. Check the verified Render service origin and status.\n');process.exitCode=1;}
}
