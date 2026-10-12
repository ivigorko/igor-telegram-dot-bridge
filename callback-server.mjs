import http from 'node:http';
import {pathToFileURL} from 'node:url';
import {isIP} from 'node:net';
import {safeRequest, destination} from './security.mjs';
import {unb64, verifyInternal, signInternalResponse} from './lib/crypto.mjs';

const ROUTE='/internal/callback', RELAY_ROUTE='/internal/relay-callback', MAX_BODY=512*1024, MAX_CALLBACK=262144;
const exactKeys=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
function allowedRelayBody(raw){
  const value=JSON.parse(raw);
  // Preserve the signed bytes, but reject duplicate/escaped keys or hidden
  // overwritten values that JSON.parse alone would silently discard. The relay
  // emits JSON.stringify bodies; no reserialization is performed for delivery.
  if(JSON.stringify(value)!==raw)return false;
  if(exactKeys(value,['type','challenge']))return value.type==='verification'&&typeof value.challenge==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.challenge);
  return exactKeys(value,['eventId','name','timestamp','data','cursor'])
    &&typeof value.eventId==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value.eventId)
    &&value.name==='telegram.ingress.available'
    &&typeof value.timestamp==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.timestamp)
    &&Number.isFinite(Date.parse(value.timestamp))&&new Date(value.timestamp).toISOString()===value.timestamp
    &&exactKeys(value.data,['available','generation'])&&value.data.available===true
    &&Number.isSafeInteger(value.data.generation)&&value.data.generation>0&&value.cursor===null;
}
export function loadConfig(env=process.env) {
  const key=env.CALLBACK_HMAC_KEY;
  if(unb64(key).length!==32) throw Error('CALLBACK_HMAC_KEY must be a canonical base64 256-bit key');
  const relayEnabled=env.RELAY_CALLBACK_ENABLED==='true';
  let relayKey;
  if(relayEnabled){
    relayKey=env.RELAY_CALLBACK_HMAC_KEY;
    try{if(unb64(relayKey).length!==32)throw Error();}
    catch{throw Error('RELAY_CALLBACK_HMAC_KEY must be a canonical base64 256-bit key when relay callback is enabled');}
    if(relayKey===key)throw Error('RELAY_CALLBACK_HMAC_KEY must differ from CALLBACK_HMAC_KEY');
  }
  const hosts=(env.MCP_CALLBACK_HOSTS||'').split(',').map(x=>x.trim());
  if(!hosts.length||hosts.some(h=>!h||h!==h.toLowerCase()||h.length>253||isIP(h)||h.endsWith('.local')||!h.includes('.')||h.split('.').some(s=>!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)))) throw Error('exact callback DNS hosts required');
  const port=Number(env.PORT||10000);
  if(!Number.isInteger(port)||port<1||port>65535) throw Error('invalid PORT');
  return {key,hosts:[...new Set(hosts)],port,relayEnabled,relayKey};
}
export function createCallbackServer(config,{transport=safeRequest,now=Date.now}={}) {
  // Validate even programmatic callers; dependency injection is for local tests only.
  const {key,hosts,relayEnabled,relayKey}=loadConfig({CALLBACK_HMAC_KEY:config.key,MCP_CALLBACK_HOSTS:config.hosts?.join(','),RELAY_CALLBACK_ENABLED:config.relayEnabled===true?'true':'false',RELAY_CALLBACK_HMAC_KEY:config.relayKey});
  // Each route has exactly one key and a separate replay namespace. These bounded
  // in-memory caches are lost on restart; durable nonce/operation fences belong
  // in the private core and relay, not in this stateless callback transport.
  const routes=new Map([[ROUTE,{key,used:new Map()}]]);
  if(relayEnabled)routes.set(RELAY_ROUTE,{key:relayKey,used:new Map()});
  let active=0; // Shared outbound capacity, never a separate relay allowance.
  const server=http.createServer({maxHeaderSize:16384},async(req,res)=>{
    const route=routes.get(req.url);
    const reply=async(status,value,signed=false)=>{
      const body=JSON.stringify(value),headers={'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'};
      if(signed) headers['x-bridge-response-signature']=await signInternalResponse(route.key,req.headers['x-bridge-id'],body);
      res.writeHead(status,headers);res.end(body);
    };
    try {
      if(req.method==='GET'&&req.url==='/healthz') return await reply(200,{ok:true,service:'callback-only'});
      if(req.method!=='POST'||!route) return await reply(404,{error:'not found'});
      if(req.headers.origin) return await reply(403,{error:'browser calls disabled'});
      if(!req.headers['x-bridge-id']||!req.headers['x-bridge-timestamp']||!req.headers['x-bridge-signature']) return await reply(401,{error:'invalid signature'});
      if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||'')) return await reply(415,{error:'JSON required'});
      if(req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')return await reply(415,{error:'encoding unsupported'});
      if(Number(req.headers['content-length'])>MAX_BODY) return await reply(413,{error:'body limit'});
      const parts=[];let size=0;
      for await(const part of req){size+=part.length;if(size>MAX_BODY)return await reply(413,{error:'body limit'});parts.push(part);}
      const body=Buffer.concat(parts).toString('utf8');
      if(!await verifyInternal(route.key,req.url,body,new Headers(req.headers),now()))return await reply(401,{error:'invalid signature'});
      const {used}=route;
      for(const [id,expires] of used)if(expires<=now())used.delete(id);
      const id=req.headers['x-bridge-id'];
      if(used.has(id)||used.size>=10000)return await reply(409,{error:'request replayed or replay cache full'},true);
      // Cover the entire +/-300 second timestamp window, including future-dated requests.
      used.set(id,now()+610000);
      if(active>=16)return await reply(503,{error:'capacity unavailable'},true);
      let data;
      try {
        data=JSON.parse(body);
        if(!data||Array.isArray(data)||typeof data.url!=='string'||data.url.length>8192||typeof data.body!=='string'||Buffer.byteLength(data.body)>MAX_CALLBACK)throw Error();
        // Delegated relay signing can carry only a verification challenge or a
        // generic content-free availability wake. Core compatibility is intact.
        if(req.url===RELAY_ROUTE&&!allowedRelayBody(data.body))throw Error();
        destination(data.url,hosts);
        const headers={'content-type':'application/json'};
        for(const name of ['webhook-id','webhook-timestamp','webhook-signature','X-MCP-Subscription-Id']) {
          const value=data.headers?.[name];
          if(typeof value!=='string'||!value.length||value.length>2048||/[\r\n\0]/.test(value))throw Error();
          headers[name]=value;
        }
        data={url:data.url,body:data.body,headers};
      }catch{return await reply(400,{error:'invalid callback payload'},true);}
      active++;
      try {
        const r=await transport(data.url,{hosts,headers:data.headers,body:data.body,limit:MAX_CALLBACK,timeoutMs:15000});
        if(!Number.isInteger(r.status)||r.status<100||r.status>599||!Buffer.isBuffer(r.body)||r.body.length>MAX_CALLBACK)throw Error();
        return await reply(200,{status:r.status,body:r.body.toString('utf8')},true);
      }catch{return await reply(502,{error:'callback transport unavailable'},true);}
      finally{active--;}
    }catch{if(!res.headersSent)await reply(400,{error:'invalid request'});else res.destroy();}
  });
  server.requestTimeout=20000;server.headersTimeout=10000;server.keepAliveTimeout=5000;
  server.maxRequestsPerSocket=100;
  return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const config=loadConfig(),server=createCallbackServer(config);
  server.listen(config.port,'0.0.0.0');
  for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{
    server.close(()=>process.exit(0));
    setTimeout(()=>{server.closeAllConnections();process.exit(1);},20000).unref();
  });
}
