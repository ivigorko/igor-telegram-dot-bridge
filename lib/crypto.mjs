const enc=new TextEncoder();
export const b64=bytes=>{let text='';for(let i=0;i<bytes.length;i+=8192)text+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(text);};
export const unb64=s=>{if(typeof s!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(s))throw Error('invalid base64');const bytes=Uint8Array.from(atob(s),c=>c.charCodeAt(0));if(b64(bytes)!==s)throw Error('invalid base64');return bytes;};
export const equal=(a,b)=>{if(typeof a!=='string'||typeof b!=='string')return false;const x=enc.encode(a),y=enc.encode(b);let diff=x.length^y.length;for(let i=0;i<Math.max(x.length,y.length);i++)diff|=(x[i]??0)^(y[i]??0);return diff===0;};
export const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
export async function digest(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(canonical(value))))].map(x=>x.toString(16).padStart(2,'0')).join('');}
async function mac(key,data){const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);return b64(new Uint8Array(await crypto.subtle.sign('HMAC',k,enc.encode(data))));}
export function eventKey(secret){if(!secret?.startsWith('whsec_'))throw Error('invalid event key');const key=unb64(secret.slice(6));if(key.length<24||key.length>64)throw Error('invalid event key');return key;}
export async function signEvent(secret,id,body,sub,now=Date.now()){
 const timestamp=String(Math.floor(now/1000));return {'content-type':'application/json','webhook-id':id,'webhook-timestamp':timestamp,'webhook-signature':'v1,'+await mac(eventKey(secret),`${id}.${timestamp}.${body}`),'X-MCP-Subscription-Id':sub};
}
function internalKey(key){const bytes=unb64(key);if(bytes.length!==32)throw Error('256-bit internal key required');return bytes;}
// Only for the separate ingress/egress/preprocessing helper, never MCP user auth.
export async function internalHeaders(key,route,body,now=Date.now()){
 const id=crypto.randomUUID(),ts=String(Math.floor(now/1000));
 return {'content-type':'application/json','x-bridge-id':id,'x-bridge-timestamp':ts,'x-bridge-signature':await mac(internalKey(key),`${route}.${id}.${ts}.${body}`)};
}
export async function verifyInternal(key,route,body,headers,now=Date.now()){
 try{const id=headers.get('x-bridge-id'),ts=headers.get('x-bridge-timestamp'),signature=headers.get('x-bridge-signature');if(!id||id.length>128||!/^\d{10}$/.test(ts??'')||Math.abs(now/1000-Number(ts))>300)return false;
 return equal(signature,await mac(internalKey(key),`${route}.${id}.${ts}.${body}`));}catch{return false;}
}
export async function signInternalResponse(key,id,body){return mac(internalKey(key),`response.${id}.${body}`);}
export async function verifyInternalResponse(key,id,body,signature){return equal(signature,await signInternalResponse(key,id,body));}
export async function seal(key,value){const aes=await crypto.subtle.importKey('raw',internalKey(key),'AES-GCM',false,['encrypt']);const iv=crypto.getRandomValues(new Uint8Array(12));const data=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},aes,enc.encode(JSON.stringify(value))));return b64(iv)+'.'+b64(data);}
export async function open(key,text){const [iv,data]=text.split('.');const aes=await crypto.subtle.importKey('raw',internalKey(key),'AES-GCM',false,['decrypt']);return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(iv)},aes,unb64(data))));}
