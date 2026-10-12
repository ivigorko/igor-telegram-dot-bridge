import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import https from 'node:https';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {createCallbackServer,loadConfig} from './callback-server.mjs';
import {internalHeaders,verifyInternalResponse} from './lib/crypto.mjs';
import {safeRequest,publicIP} from './security.mjs';

// Deterministic test-only values. No deployment credentials or environment reads.
const coreKey=Buffer.alloc(32,17).toString('base64');
const relayKey=Buffer.alloc(32,29).toString('base64');
const coreRoute='/internal/callback',relayRoute='/internal/relay-callback';
const hosts=['callbacks.example.com'];
const env={CALLBACK_HMAC_KEY:coreKey,MCP_CALLBACK_HOSTS:hosts[0]};
const routes=[[coreRoute,coreKey],[relayRoute,relayKey]];
const wake=()=>({eventId:'wake-fixture',name:'telegram.ingress.available',timestamp:'2026-10-12T12:00:00.000Z',data:{available:true,generation:1},cursor:null});
const challenge='59a725b4-aec2-4c67-bf97-e075d1756b52';
const payload=()=>({url:'https://callbacks.example.com/events?fixed=1',body:JSON.stringify(wake()),headers:{'webhook-id':'wake-fixture','webhook-timestamp':'1791806400','webhook-signature':'v1,test-signed-upstream','X-MCP-Subscription-Id':'sub-fixture',Authorization:'must-not-forward','x-bridge-signature':'must-not-forward','host':'must-not-forward'}});
async function fixture(t,{config={key:coreKey,hosts,relayEnabled:true,relayKey},transport=async()=>({status:204,body:Buffer.alloc(0)}),now=Date.now}={}){
  const server=createCallbackServer(config,{transport,now});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
  const base=`http://127.0.0.1:${server.address().port}`;
  async function send(route=relayRoute,key=relayKey,data=payload(),options={}){
    const body=typeof data==='string'?data:JSON.stringify(data);
    const headers=await internalHeaders(key,options.signedRoute??route,body,options.timestamp??now());
    if(options.id){
      headers['x-bridge-id']=options.id;
      headers['x-bridge-signature']=createHmac('sha256',Buffer.from(key,'base64')).update(`${options.signedRoute??route}.${options.id}.${headers['x-bridge-timestamp']}.${body}`).digest('base64');
    }
    const response=await fetch(base+route,{method:options.method??'POST',body,headers:{...headers,...options.headers}});
    return {response,id:headers['x-bridge-id']};
  }
  return {base,send};
}
async function assertSigned(result,key,status){
  assert.equal(result.response.status,status);
  const raw=await result.response.text(),signature=result.response.headers.get('x-bridge-response-signature');
  assert.equal(await verifyInternalResponse(key,result.id,raw,signature),true);
  assert.equal(await verifyInternalResponse(key===coreKey?relayKey:coreKey,result.id,raw,signature),false);
  assert.equal(await verifyInternalResponse(key,'wrong-request-id',raw,signature),false);
  assert.equal(await verifyInternalResponse(key,result.id,raw+' ',signature),false);
  return JSON.parse(raw);
}

test('relay is disabled by default, including a supplied key without literal true opt-in',async t=>{
  for(const enabled of [undefined,'false','TRUE','1',true,'true ']){
    const config=loadConfig({...env,RELAY_CALLBACK_ENABLED:enabled,RELAY_CALLBACK_HMAC_KEY:relayKey});
    assert.equal(config.relayEnabled,false);assert.equal(config.relayKey,undefined);
    const {send}=await fixture(t,{config});
    const relay=await send();assert.equal(relay.response.status,404);assert.equal(relay.response.headers.get('x-bridge-response-signature'),null);
    await assertSigned(await send(coreRoute,coreKey),coreKey,200);
  }
});
test('relay startup requires its own distinct canonical 256-bit key; core key remains mandatory',()=>{
  for(const candidate of [undefined,'','wrong',Buffer.alloc(31).toString('base64'),Buffer.alloc(33).toString('base64'),relayKey.replace(/=$/,''),coreKey]){
    assert.throws(()=>loadConfig({...env,RELAY_CALLBACK_ENABLED:'true',RELAY_CALLBACK_HMAC_KEY:candidate}),/RELAY_CALLBACK_HMAC_KEY/);
    assert.throws(()=>createCallbackServer({key:coreKey,hosts,relayEnabled:true,relayKey:candidate}));
  }
  assert.throws(()=>loadConfig({MCP_CALLBACK_HOSTS:hosts[0],RELAY_CALLBACK_ENABLED:'true',RELAY_CALLBACK_HMAC_KEY:relayKey}));
  const config=loadConfig({...env,RELAY_CALLBACK_ENABLED:'true',RELAY_CALLBACK_HMAC_KEY:relayKey});
  assert.equal(config.key,coreKey);assert.equal(config.relayKey,relayKey);assert.equal(config.relayEnabled,true);assert.equal(config.port,10000);
});
test('each route accepts only its own key, exact path and path-bound request signature',async t=>{
  let calls=0;const {base,send}=await fixture(t,{transport:async()=>{calls++;return {status:204,body:Buffer.alloc(0)};}});
  for(const [route,key] of routes){
    const otherKey=key===coreKey?relayKey:coreKey,otherRoute=route===coreRoute?relayRoute:coreRoute;
    for(const result of [await send(route,otherKey),await send(route,key,payload(),{signedRoute:otherRoute}),await send(route,otherKey,payload(),{signedRoute:otherRoute})]){
      assert.equal(result.response.status,401);assert.equal(result.response.headers.get('x-bridge-response-signature'),null);
    }
    for(const suffix of ['?x=1','/','%2f','/..%2fcallback'])assert.equal((await send(route+suffix,key)).response.status,404);
    // fetch normalizes dot segments before sending, so its resulting known route
    // must still reject a signature bound to the unnormalized path.
    assert.equal((await send(route+'/../callback',key)).response.status,401);
    assert.equal((await fetch(base+route)).status,404);
    assert.equal((await send(route,key,payload(),{method:'PUT'})).response.status,404);
  }
  assert.equal(calls,0);
});
test('both routes forward pre-signed bytes only and sign responses with their own key',async t=>{
  let calls=0;const {send}=await fixture(t,{transport:async(url,options)=>{
    calls++;assert.equal(url,payload().url);assert.equal(options.body,payload().body);
    assert.deepEqual(options.headers,{'content-type':'application/json','webhook-id':'wake-fixture','webhook-timestamp':'1791806400','webhook-signature':'v1,test-signed-upstream','X-MCP-Subscription-Id':'sub-fixture'});
    assert.deepEqual(options.hosts,hosts);assert.equal(options.timeoutMs,15000);assert.equal(options.limit,262144);
    return {status:202,body:Buffer.from('{"accepted":true}')};
  }});
  for(const [route,key] of routes)assert.deepEqual(await assertSigned(await send(route,key),key,200),{status:202,body:'{"accepted":true}'});
  assert.equal(calls,2);
});
test('relay permits only exact generic wake and UUID verification schemas without changing signed bytes',async t=>{
  const forwarded=[];const {send}=await fixture(t,{transport:async(_url,options)=>{forwarded.push(options);return {status:200,body:Buffer.from(JSON.stringify({challenge}))};}});
  const verification={...payload(),body:JSON.stringify({type:'verification',challenge}),headers:{...payload().headers,'webhook-id':'verify_relay_'+challenge}};
  await assertSigned(await send(relayRoute,relayKey,verification),relayKey,200);
  for(const event of [wake(),{...wake(),eventId:'tgr_'+challenge+'_8',data:{available:true,generation:8}},{...wake(),eventId:'x'.repeat(128),data:{available:true,generation:Number.MAX_SAFE_INTEGER}}])await assertSigned(await send(relayRoute,relayKey,{...payload(),body:JSON.stringify(event)}),relayKey,200);
  assert.equal(forwarded[0].body,verification.body);assert.equal(forwarded[0].headers['webhook-id'],verification.headers['webhook-id']);assert.equal(forwarded[1].body,payload().body);assert.equal(forwarded.length,4);
});
test('relay rejects message/identity content, foreign event types and all schema extras before egress',async t=>{
  let calls=0;const {send}=await fixture(t,{transport:async()=>{calls++;throw Error('no egress expected');}});
  const invalid=[null,[],{},'message',{type:'message',message:'private content'},{type:'verification',challenge:'not-a-uuid'},{type:'verification',challenge:{value:challenge}},{type:'verification',challenge,message:'private content'},{type:'verification',challenge,ownerId:'123'},
    {...wake(),name:'telegram.message'},{...wake(),message:'private content'},{...wake(),telegramId:'123'},{...wake(),data:{available:true,generation:1,message:'private content'}},{...wake(),data:{available:true,generation:1,identity:{telegramId:'123'}}},
    {...wake(),data:{available:true,generation:1,guest:{authorized:true}}},{...wake(),data:{available:true}},{...wake(),data:{available:false,generation:1}},{...wake(),data:{available:'true',generation:1}},{...wake(),data:[true,1]},
    {...wake(),cursor:'private-cursor'},{...wake(),timestamp:'2026-10-12T12:00:00Z'},{...wake(),timestamp:'2026-02-30T12:00:00.000Z'},{...wake(),timestamp:'invalid'},
    {...wake(),eventId:''},{...wake(),eventId:'x'.repeat(129)},{...wake(),eventId:'private message text'},
    ...[0,-1,1.5,'1',null,Number.MAX_SAFE_INTEGER+1].map(generation=>({...wake(),data:{available:true,generation}}))];
  for(const event of invalid)assert.deepEqual(await assertSigned(await send(relayRoute,relayKey,{...payload(),body:JSON.stringify(event)}),relayKey,400),{error:'invalid callback payload'});
  for(const name of Object.keys(wake())){const event=wake();delete event[name];await assertSigned(await send(relayRoute,relayKey,{...payload(),body:JSON.stringify(event)}),relayKey,400);}
  assert.equal(calls,0);
});
test('relay rejects duplicate-key and escaped-key content smuggling without normalizing signatures',async t=>{
  let calls=0;const {send}=await fixture(t,{transport:async()=>{calls++;throw Error('no egress expected');}});
  const valid=payload().body;
  const invalid=[valid.replace('"data":','"data":{"message":"private content"},"data":'),valid.replace('"name":','"name":"telegram.message","name":'),valid.replace('"data":','"da\\u0074a":'),valid.replace('"available":true','"available":{"identity":"private"},"available":true'),valid+'{}',' '+valid,JSON.stringify(wake(),null,2),'{'];
  for(const body of invalid)await assertSigned(await send(relayRoute,relayKey,{...payload(),body}),relayKey,400);
  assert.equal(calls,0);
});
test('relay body restrictions never change existing core callback content compatibility',async t=>{
  const forwarded=[];const {send}=await fixture(t,{transport:async(_url,options)=>{forwarded.push(options.body);return {status:204,body:Buffer.alloc(0)};}});
  const bodies=[JSON.stringify({type:'verification',challenge:'legacy-arbitrary-challenge'}),JSON.stringify({name:'telegram.message',data:{message:'legacy content',telegramId:'123'}}),'legacy signed raw body'];
  for(const body of bodies)await assertSigned(await send(coreRoute,coreKey,{...payload(),body}),coreKey,200);
  assert.deepEqual(forwarded,bodies);
});
test('replay caches are route-separated, and failed cross-key authorization cannot consume another nonce',async t=>{
  let calls=0;const {send}=await fixture(t,{transport:async()=>{calls++;return {status:204,body:Buffer.alloc(0)};}});
  const options={id:'same-request-id-on-both-routes'};
  assert.equal((await send(relayRoute,coreKey,payload(),options)).response.status,401);
  for(const [route,key] of routes){
    await assertSigned(await send(route,key,payload(),options),key,200);
    assert.deepEqual(await assertSigned(await send(route,key,payload(),options),key,409),{error:'request replayed or replay cache full'});
  }
  assert.equal(calls,2);
});
test('concurrent duplicate relay requests egress only once',async t=>{
  let calls=0;const {send}=await fixture(t,{transport:async()=>{calls++;return {status:204,body:Buffer.alloc(0)};}});
  const results=await Promise.all(Array.from({length:8},()=>send(relayRoute,relayKey,payload(),{id:'concurrent-relay-id'})));
  assert.deepEqual(results.map(r=>r.response.status).sort(),[200,409,409,409,409,409,409,409]);assert.equal(calls,1);
});
test('relay replay fence includes future-dated requests throughout their signed validity window',async t=>{
  let now=1791806400000,calls=0;const {send}=await fixture(t,{now:()=>now,transport:async()=>{calls++;return {status:204,body:Buffer.alloc(0)};}});
  const options={id:'future-dated-relay-id',timestamp:now+290000};
  await assertSigned(await send(relayRoute,relayKey,payload(),options),relayKey,200);
  now+=301000;await assertSigned(await send(relayRoute,relayKey,payload(),options),relayKey,409);assert.equal(calls,1);
});
test('relay validation preserves body, header, URL, origin, encoding and timestamp restrictions',async t=>{
  let calls=0;const {send}=await fixture(t,{transport:async()=>{calls++;throw Error('no egress expected');}});
  for(const [headers,status] of [[{origin:'https://evil.example'},403],[{'content-type':'text/plain'},415],[{'content-encoding':'gzip'},415],[{'x-bridge-signature':'bad'},401],[{'x-bridge-timestamp':'1000000000'},401]]){
    const result=await send(relayRoute,relayKey,payload(),{headers});assert.equal(result.response.status,status);assert.equal(result.response.headers.get('x-bridge-response-signature'),null);
  }
  for(const invalid of ['{',null,[],{}, {...payload(),body:'x'.repeat(262145)}, {...payload(),url:'https://callbacks.example.com/'+ 'x'.repeat(8192)}])await assertSigned(await send(relayRoute,relayKey,invalid),relayKey,400);
  for(const url of ['http://callbacks.example.com','https://evil.example.com','https://callbacks.example.com.evil.test','https://callbacks.example.com:444','https://user:pass@callbacks.example.com','https://127.0.0.1','https://[::1]','https://callbacks.example.com/#fragment'])await assertSigned(await send(relayRoute,relayKey,{...payload(),url}),relayKey,400);
  for(const name of ['webhook-id','webhook-timestamp','webhook-signature','X-MCP-Subscription-Id'])for(const value of [undefined,'','x\r\ny','x\0y','x'.repeat(2049)])await assertSigned(await send(relayRoute,relayKey,{...payload(),headers:{...payload().headers,[name]:value}}),relayKey,400);
  assert.equal((await send(relayRoute,relayKey,'x'.repeat(524289))).response.status,413);assert.equal(calls,0);
});
test('relay transport failures use relay response signing and never expose internal details',async t=>{
  const responses=[()=>{throw Error('private diagnostic');},()=>({status:302,body:Buffer.from('redirect')}),()=>({status:200,body:Buffer.alloc(262145)}),()=>({status:999,body:Buffer.alloc(0)})];
  const {send}=await fixture(t,{transport:async()=>responses.shift()()});
  assert.deepEqual(await assertSigned(await send(),relayKey,502),{error:'callback transport unavailable'});
  assert.deepEqual(await assertSigned(await send(),relayKey,200),{status:302,body:'redirect'});
  await assertSigned(await send(),relayKey,502);await assertSigned(await send(),relayKey,502);
});
test('outbound capacity of 16 is shared between core and relay routes',async t=>{
  let entered=0,release;const gate=new Promise(resolve=>{release=resolve;});
  const {send}=await fixture(t,{transport:async()=>{entered++;await gate;return {status:204,body:Buffer.alloc(0)};}});
  const pending=Array.from({length:16},(_,i)=>send(...routes[i%2]));
  try{
    for(let i=0;i<200&&entered<16;i++)await new Promise(resolve=>setTimeout(resolve,5));
    assert.equal(entered,16);
    for(const [route,key] of routes)assert.deepEqual(await assertSigned(await send(route,key),key,503),{error:'capacity unavailable'});
    assert.equal(entered,16);
  }finally{release();await Promise.all(pending);}
});
test('both routes block private, reserved and mixed DNS answers before HTTPS connection',async t=>{
  const original=https.request;let connections=0;
  https.request=()=>{connections++;throw Error('unexpected connection');};t.after(()=>{https.request=original;});
  let addresses=[];
  const {send}=await fixture(t,{transport:(url,options)=>safeRequest(url,{...options,resolver:async()=>addresses})});
  const blocked=['0.0.0.0','10.0.0.1','127.0.0.1','169.254.169.254','172.16.0.1','192.168.0.1','100.64.0.1','198.18.0.1','192.0.2.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','2002:0808:0808::1','3fff::1'];
  for(const address of blocked){
    assert.equal(publicIP(address),false);
    const candidate={address,family:address.includes(':')?6:4};
    for(const values of [[candidate],[{address:'8.8.8.8',family:4},candidate]]){
      addresses=values;
      for(const [route,key] of routes)await assertSigned(await send(route,key),key,502);
    }
  }
  addresses=[];for(const [route,key] of routes)await assertSigned(await send(route,key),key,502);
  assert.equal(connections,0);
});
test('both routes pin public IPv4/IPv6 with original TLS SNI and never follow redirects',async t=>{
  const original=https.request;let connections=0,current;
  t.after(()=>{https.request=original;});
  https.request=(options,done)=>{
    connections++;assert.equal(options.hostname,hosts[0]);assert.equal(options.servername,hosts[0]);assert.equal(options.port,443);assert.equal(options.path,'/events?fixed=1');assert.equal(options.method,'POST');assert.equal(options.agent,false);
    options.lookup(options.hostname,{all:true},(error,addresses)=>{assert.equal(error,null);assert.deepEqual(addresses,[current]);});
    options.lookup(options.hostname,{all:false},(error,address,family)=>{assert.equal(error,null);assert.equal(address,current.address);assert.equal(family,current.family);});
    const request=new EventEmitter();request.setTimeout=()=>request;
    request.end=body=>{assert.equal(body,payload().body);const response=Readable.from([Buffer.from('redirect')]);response.statusCode=302;response.headers={location:'https://127.0.0.1/secret'};done(response);};return request;
  };
  const {send}=await fixture(t,{transport:(url,options)=>safeRequest(url,{...options,resolver:async()=>[current,{address:'1.1.1.1',family:4}]})});
  for(const address of [{address:'8.8.8.8',family:4},{address:'2606:4700:4700::1111',family:6}]){
    current=address;assert.equal(publicIP(address.address),true);
    for(const [route,key] of routes)assert.deepEqual(await assertSigned(await send(route,key),key,200),{status:302,body:'redirect'});
  }
  assert.equal(connections,4);
});
