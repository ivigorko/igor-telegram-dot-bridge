import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {safeRequest} from './security.mjs';
test('Node24 all:true lookup receives ONLY validated pinned address and original TLS hostname',async t=>{
  const original=https.request;let calls=0;
  t.after(()=>{https.request=original;});
  https.request=(options,done)=>{
    calls++;assert.equal(options.hostname,'callbacks.example.com');assert.equal(options.servername,'callbacks.example.com');assert.equal(options.agent,false);assert.equal(options.path,'/event?x=1');
    options.lookup(options.hostname,{all:true},(err,addresses)=>{assert.equal(err,null);assert.deepEqual(addresses,[{address:'8.8.8.8',family:4}]);});
    options.lookup(options.hostname,{all:false},(err,address,family)=>{assert.equal(err,null);assert.equal(address,'8.8.8.8');assert.equal(family,4);});
    const req=new EventEmitter();req.setTimeout=()=>req;req.end=()=>{const res=Readable.from([Buffer.from('{}')]);res.statusCode=302;res.headers={location:'https://evil.example.com'};done(res);};return req;
  };
  const r=await safeRequest('https://callbacks.example.com/event?x=1',{hosts:['callbacks.example.com'],resolver:async()=>[{address:'8.8.8.8',family:4},{address:'1.1.1.1',family:4}]});
  assert.equal(r.status,302);assert.equal(calls,1);
});
test('abort cancels unresolved DNS within requested transport budget',async()=>{
  const controller=new AbortController();const result=safeRequest('https://callbacks.example.com',{hosts:['callbacks.example.com'],resolver:()=>new Promise(()=>{}),signal:controller.signal});controller.abort();await assert.rejects(result,/cancelled/);
});
test('DNS transport timeout is bounded',async()=>{
  const started=Date.now();await assert.rejects(safeRequest('https://callbacks.example.com',{hosts:['callbacks.example.com'],resolver:()=>new Promise(()=>{}),timeoutMs:10}));assert.ok(Date.now()-started<1000);
});
