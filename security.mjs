import {createHmac, timingSafeEqual, randomUUID} from 'node:crypto';
import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import https from 'node:https';
export const equal = (a,b) => typeof a==='string' && typeof b==='string' && Buffer.byteLength(a)===Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a),Buffer.from(b));
export function signingKey(secret) {
 if(typeof secret!=='string'||!/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) throw Error('invalid signing key');
 const key=Buffer.from(secret.slice(6),'base64');
 if(key.length<24||key.length>64||key.toString('base64')!==secret.slice(6)) throw Error('invalid signing key');
 return key;
}
export function signed(secret,id,body,sub,now=Date.now()) {
 const timestamp=String(Math.floor(now/1000));
 const sig=createHmac('sha256',signingKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64');
 return {'content-type':'application/json','webhook-id':id,'webhook-timestamp':timestamp,'webhook-signature':`v1,${sig}`,'X-MCP-Subscription-Id':sub};
}
export function publicIP(ip) {
 if(isIP(ip)===6) {
  const [first,second]=ip.toLowerCase().split(':');
  return /^[23][0-9a-f]{3}$/.test(first) && first!=='2002' && first!=='3fff' && !(first==='2001'&&(parseInt(second||'0',16)<=0x1ff||parseInt(second||'0',16)===0xdb8));
 }
 if(isIP(ip)!==4) return false;
 const [a,b,c]=ip.split('.').map(Number);
 return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0||b===2||b===88&&c===99)||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113);
}
export function destination(raw,hosts) {
 const u=new URL(raw);
 if(u.protocol!=='https:'||u.username||u.password||u.hash||(u.port&&u.port!=='443')||!hosts.includes(u.hostname)||isIP(u.hostname)) throw Error('blocked destination');
 return u;
}
// All answers are checked per connection. Connect directly to a validated address;
// retain hostname/SNI for TLS certificate verification. No redirects or proxy env.
export async function safeRequest(raw,{method='POST',headers={},body='',limit=262144,hosts=[],resolver=lookup,signal,timeoutMs=15000}={}) {
 const u=destination(raw,hosts);
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw Error('invalid transport deadline');
 if(!Number.isSafeInteger(limit)||limit<1||limit>32*1024*1024)throw Error('invalid response limit');
 const deadline=AbortSignal.timeout(timeoutMs),combined=signal?AbortSignal.any([signal,deadline]):deadline;
 if(combined.aborted)throw Error('transport cancelled');
 let dnsTimer,onDNSAbort;let addresses;
 try{
  addresses=await Promise.race([
   resolver(u.hostname,{all:true}),
   new Promise((_,reject)=>{
    dnsTimer=setTimeout(()=>reject(Error('DNS timeout')),Math.min(5000,timeoutMs));
    onDNSAbort=()=>reject(Error('transport cancelled'));
    combined.addEventListener('abort',onDNSAbort,{once:true});
    if(combined.aborted)onDNSAbort();
   })
  ]);
 }finally{clearTimeout(dnsTimer);if(onDNSAbort)combined.removeEventListener('abort',onDNSAbort);}
 if(combined.aborted)throw Error('transport cancelled');
 if(!Array.isArray(addresses)||!addresses.length||addresses.some(x=>!publicIP(x.address))) throw Error('blocked address');
 const address=addresses[0];
 return new Promise((resolve,reject)=>{
  const req=https.request({hostname:u.hostname,servername:u.hostname,port:443,path:u.pathname+u.search,method,headers,agent:false,signal:combined,lookup:(_h,options,cb)=>options.all?cb(null,[address]):cb(null,address.address,address.family)},res=>{
   let size=0; const parts=[];
   res.on('data',part=>{size+=part.length;if(size>limit){res.destroy();reject(Error('response too large'));}else parts.push(part);});
   res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(parts)}));res.on('error',()=>reject(Error('transport failure')));
  });
  req.setTimeout(Math.min(10000,timeoutMs),()=>req.destroy());req.on('error',()=>reject(Error('transport failure')));req.end(body);
 });
}
export async function verifyCallback(url,secret,id,hosts,transport=safeRequest) {
 const challenge=randomUUID(); const body=JSON.stringify({type:'verification',challenge});
 try {
  destination(url,hosts);signingKey(secret);
  const r=await transport(url,{hosts,body,headers:signed(secret,`verification_${randomUUID()}`,body,id)});
  if(r.status<200||r.status>=300||!equal(JSON.parse(r.body).challenge,challenge)) throw Error();
 } catch { const e=Error('callback verification failed');e.code=-32015;e.reason='challenge_failed';throw e; }
}
