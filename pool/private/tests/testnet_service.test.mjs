import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';
import {execFileSync,spawn} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createTestnetService} from '../testnet_service.mjs';
import {createPrivateGateway} from '../server.mjs';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync,X509Certificate} from 'node:crypto';
import {validateTlsIdentity} from '../tls_identity.mjs';

const vector=JSON.parse(readFileSync(new URL('../../../meepow/vectors/block_vectors_v16_devnet.json',import.meta.url))).vectors[1];
const tokenA='a'.repeat(64),tokenB='b'.repeat(64);
const certDir=mkdtempSync(join(tmpdir(),'meep-tls-'));
const openssl=existsSync('C:/Program Files/Git/usr/bin/openssl.exe')?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl';
execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(certDir,'key.pem'),'-out',join(certDir,'cert.pem'),
  '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{timeout:15000,stdio:'ignore',windowsHide:true});
const tls={key:readFileSync(join(certDir,'key.pem')),cert:readFileSync(join(certDir,'cert.pem'))};
test.after(()=>rmSync(certDir,{recursive:true}));
test('TLS identity refuses wrong host, key, expiry and partial wildcard certificates',()=>{
 const endsUtcUnix=Math.floor(Date.now()/1000)+60;
 assert.doesNotThrow(()=>validateTlsIdentity({...tls,origin:'https://localhost',endsUtcUnix}));
 assert.throws(()=>validateTlsIdentity({...tls,origin:'https://wrong.invalid',endsUtcUnix}),/hostname/);
 const wrong=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey;
 assert.throws(()=>validateTlsIdentity({...tls,key:wrong,origin:'https://localhost',endsUtcUnix}),/private key/);
 const afterExpiry=Math.ceil(Date.parse(new X509Certificate(tls.cert).validTo)/1000)+1;
 assert.throws(()=>validateTlsIdentity({...tls,origin:'https://localhost',endsUtcUnix:afterExpiry}),/validity/);
 const partial=join(certDir,'partial.pem');
 execFileSync(openssl,['req','-x509','-new','-key',join(certDir,'key.pem'),'-out',partial,'-days','1',
  '-subj','/CN=fixture','-addext','subjectAltName=DNS:f*.example.test'],{timeout:10000,stdio:'ignore',windowsHide:true});
 assert.throws(()=>validateTlsIdentity({key:tls.key,cert:readFileSync(partial),origin:'https://foo.example.test',endsUtcUnix}),/hostname/);
});
async function fixture(t,extra={}) {
 let available=true,bytes=2n*1024n**3n,clock=0,calls=0,healthGate,healthEntered,identity={nettype:'testnet',version:'fixture-build',genesis:'c'.repeat(64),timestamp:extra.experiment?.genesisUtcUnix};
 const rpc=http.createServer(async(req,res)=>{
  let text='';for await(const c of req)text+=c;
  const q=JSON.parse(text);calls++;
  if(q.method==='get_info'&&healthGate){healthEntered();await healthGate;}
  if(!available){res.writeHead(503);return res.end('{}');}
  res.end(JSON.stringify({jsonrpc:'2.0',id:q.id,result:q.method==='get_info'?{status:'OK',height:10,nettype:identity.nettype,version:identity.version}:q.method==='get_block_header_by_height'?{status:'OK',block_header:{hash:identity.genesis,timestamp:identity.timestamp}}:{
   status:'OK',height:vector.height,wide_difficulty:'0x1',seed_hash:vector.epoch_key,seed_height:0,prev_hash:'a'.repeat(64),reserved_offset:0,
   blocktemplate_blob:vector.full_block_blob,blockhashing_blob:vector.block_hashing_blob}}));
 });
 await new Promise(ok=>rpc.listen(0,'127.0.0.1',ok));
 t.after(()=>new Promise(ok=>{rpc.closeAllConnections();rpc.close(ok);}));
 const service=await createTestnetService({endpoint:'http://127.0.0.1:'+rpc.address().port+'/json_rpc',tls,origin:'https://localhost',
  sessions:[{token:tokenA,walletAddress:'2'.repeat(95)},{token:tokenB,walletAddress:'3'.repeat(95)}],
  expectedGenesisHash:'c'.repeat(64),expectedVersion:'fixture-build',
  now:()=>clock,freeBytes:async()=>bytes,
  gatewayFactory:opts=>createPrivateGateway({...opts,nativeFactory:()=>({hashOne:()=>{throw Error('Unexpected native hash');}})}),...extra});
 t.after(()=>service.close());
 function request(path,{token=tokenA,method='GET',data,headers={},port=service.port,signal}={}) {
  return new Promise((ok,bad)=>{
   const raw=data===undefined?undefined:JSON.stringify(data);
   const req=https.request({hostname:'127.0.0.1',port,path,method,servername:'localhost',ca:tls.cert,agent:false,signal,
    headers:{Host:'localhost',Origin:'https://localhost',...(token?{'X-Meep-Session':token}:{}),
    ...(raw?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(raw)}:{}),...headers}},res=>{
     let text='';res.on('data',x=>text+=x);res.on('end',()=>ok({status:res.statusCode,text,headers:res.headers,json:()=>JSON.parse(text)}));
    });
   req.on('error',bad);req.setTimeout(20000,()=>req.destroy(Error('test request deadline')));req.end(raw);
  });
 }
 return {service,request,endpoint:'http://127.0.0.1:'+rpc.address().port+'/json_rpc',calls:()=>calls,available:x=>available=x,space:x=>bytes=x,clock:x=>clock=x,
  identity:x=>Object.assign(identity,x),
  holdHealth(){let release,entered;healthGate=new Promise(ok=>release=ok);const reached=new Promise(ok=>entered=ok);healthEntered=entered;return {reached,release:()=>{healthGate=null;release();}};}};
}
test('Real TLS verifies certificate; authorization, exact origin and host precede daemon work',async t=>{
 const f=await fixture(t);
 assert.equal((await f.request('/api/status',{token:null})).status,403);
 assert.equal((await f.request('/api/start',{method:'POST',data:{},headers:{Origin:'https://evil.example'}})).status,403);
 assert.equal((await f.request('/api/start',{method:'POST',data:{},headers:{Host:'evil.example'}})).status,403);
 assert.equal(f.calls(),0);
 const page=await f.request('/',{token:null});assert.equal(page.status,200);assert.match(page.text,/TESTNET/);
 assert.equal(page.headers['set-cookie'],undefined);assert.equal(page.headers['referrer-policy'],'no-referrer');
 assert.equal((await f.request('/readyz')).status,200);
});

test('Parallel Worker module imports and repeated starts can load the verified static snapshot',async t=>{
 const f=await fixture(t);
 const paths=['/worker.js','/wasm/meepow.mjs','/wasm/meepow.wasm','/lib/worker_core.js','/lib/shared/wasm_hasher.js','/lib/shared/search.js'];
 for(let pass=0;pass<3;pass++){
  const replies=await Promise.all(paths.map(path=>f.request(path,{token:null})));
  assert.deepEqual(replies.map(r=>r.status),paths.map(()=>200));
  assert(replies.every(r=>r.text.length>0));
 }
 assert.equal(f.calls(),0,'Serving public snapshots must not query the daemon');
});

test('Linux CLI rotates owner-only invitation files and persists revocation across restart',{skip:process.platform==='win32'?'POSIX SIGHUP deployment path':false},async t=>{
 const f=await fixture(t),dir=mkdtempSync(join(tmpdir(),'meep-cli-'));
 t.after(()=>rmSync(dir,{recursive:true}));
 const configPath=join(dir,'config.json'),inviteOutput=join(dir,'invitations.json'),keyFile=join(dir,'key.pem');
 const utc=Math.floor(Date.now()/1000),experiment={genesisUtcUnix:utc,startsUtcUnix:utc,endsUtcUnix:utc+3600};
 writeFileSync(keyFile,tls.key,{mode:0o600});writeFileSync(inviteOutput,'{}',{mode:0o600});
 writeFileSync(configPath,JSON.stringify({endpoint:f.endpoint,tls:undefined,keyFile,certFile:join(certDir,'cert.pem'),origin:'https://localhost',port:0,
  expectedGenesisHash:'c'.repeat(64),expectedVersion:'fixture-build',dataDirectory:dir,inviteOutput,nativeCommand:['never-invoked'],experiment,
  sessions:[{token:tokenA,walletAddress:'2'.repeat(95)}],incidentContact:'Local rehearsal only'}),{mode:0o600});
 async function launch(){
  const child=spawn(process.execPath,[fileURLToPath(new URL('../testnet_service.mjs',import.meta.url)),configPath],{stdio:['ignore','pipe','pipe']});
  let text='',errors='';child.stdout.on('data',x=>text+=x);child.stderr.on('data',x=>errors+=x);
  t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');await Promise.race([new Promise(ok=>child.once('close',ok)),new Promise(ok=>setTimeout(ok,3000))]);});
  const until=Date.now()+10000;let port;
  while(Date.now()<until){const line=text.split('\n').find(x=>x.includes('"listening"'));if(line){port=JSON.parse(line).port;break;}assert.equal(child.exitCode,null,errors);await new Promise(ok=>setTimeout(ok,20));}
  assert(port,'CLI did not listen');return {child,port,logs:()=>text+errors};
 }
 const first=await launch();assert.equal((await f.request('/api/status',{port:first.port})).status,200);
 first.child.kill('SIGHUP');let saved;
 const until=Date.now()+5000;
 while(Date.now()<until){saved=JSON.parse(readFileSync(configPath));if(saved.sessions[0].token!==tokenA)break;await new Promise(ok=>setTimeout(ok,20));}
 const next=saved.sessions[0].token;assert.notEqual(next,tokenA);assert.equal(saved.tls,undefined);
 assert.deepEqual(saved.experiment,experiment,'Rotation must preserve absolute experiment end');
 assert.equal((await f.request('/api/status',{port:first.port})).status,403);
 assert.equal((await f.request('/api/status',{port:first.port,token:next})).status,200);
 assert(JSON.parse(readFileSync(inviteOutput)).sessions[0].url.endsWith(next));assert(!first.logs().includes(next));
 first.child.kill('SIGTERM');await new Promise(ok=>first.child.once('close',ok));
 const second=await launch();assert.equal((await f.request('/api/status',{port:second.port})).status,403);
 assert.equal((await f.request('/api/status',{port:second.port,token:next})).status,200);
});

test('Absolute epoch caps rotation, checks native genesis time and rejects a pending late start',async t=>{
 const utc=1791810000;let wall=utc*1000;
 const f=await fixture(t,{experiment:{genesisUtcUnix:utc,startsUtcUnix:utc,endsUtcUnix:utc+60},incidentContact:'<b>Local rehearsal only</b>',wallNow:()=>wall});
 const notice=(await f.request('/',{token:null})).text;assert.match(notice,/Experiment notice/);assert.match(notice,/&lt;b&gt;Local rehearsal only&lt;\/b&gt;/);assert(!notice.includes('<b>Local rehearsal'));
 f.identity({timestamp:utc+1});assert.equal((await f.request('/readyz')).status,503);
 f.identity({timestamp:utc});assert.equal((await f.request('/readyz')).status,200);
 const next=await f.service.rotate(tokenA);
 const gate=f.holdHealth(),pending=f.request('/api/start',{token:next,method:'POST',data:{}});
 await gate.reached;wall+=60000;gate.release();
 assert.equal((await pending).status,503);
 assert.equal((await f.request('/api/status',{token:next})).status,403);
 await assert.rejects(f.service.rotate(next));
 wall=utc*1000;assert.equal((await f.request('/api/status',{token:next})).status,403,'Expired epoch cannot reopen on clock rollback');
});

test('CLI refuses expired persisted experiments before listening',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'meep-expired-'));t.after(()=>rmSync(dir,{recursive:true}));
 const path=join(dir,'config.json'),utc=Math.floor(Date.now()/1000);
 writeFileSync(path,JSON.stringify({experiment:{genesisUtcUnix:utc-120,startsUtcUnix:utc-120,endsUtcUnix:utc-60},
  keyFile:join(certDir,'key.pem'),certFile:join(certDir,'cert.pem'),origin:'https://localhost',expectedGenesisHash:'c'.repeat(64),
  expectedVersion:'fixture-build',sessions:[{token:tokenA,walletAddress:'2'.repeat(95)}]}),{mode:0o600});
 const child=spawn(process.execPath,[fileURLToPath(new URL('../testnet_service.mjs',import.meta.url)),path],{stdio:['ignore','pipe','pipe']});
 let text='';child.stdout.on('data',x=>text+=x);child.stderr.on('data',x=>text+=x);
 const result=await new Promise((ok,bad)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');bad(Error('Expired CLI did not exit'));},5000);child.once('close',code=>{clearTimeout(timer);ok(code);});});
 assert.notEqual(result,0);assert(!text.includes('"listening"'));assert.match(text,/experiment not active/);
});

test('Generated operator epoch closes the real CLI and cannot be renewed by restart',async t=>{
 const f=await fixture(t),dir=mkdtempSync(join(tmpdir(),'meep-epoch-cli-'));t.after(()=>rmSync(dir,{recursive:true}));
 const reserve=http.createServer();await new Promise(ok=>reserve.listen(0,'127.0.0.1',ok));
 const listenPort=reserve.address().port;await new Promise(ok=>reserve.close(ok));
 const configPath=join(dir,'service.json'),keyFile=join(dir,'key.pem');writeFileSync(keyFile,tls.key,{mode:0o600});
 const cli=fileURLToPath(new URL('../configure_testnet.mjs',import.meta.url));
 const args=[cli,'--out',configPath,'--origin','https://localhost:'+listenPort,'--endpoint',f.endpoint,'--genesis','c'.repeat(64),
  '--genesis-utc',String(Math.floor(Date.now()/1000)),'--duration-seconds','5','--version','fixture-build',
  '--key',keyFile,'--cert',join(certDir,'cert.pem'),'--data',dir,'--native','never-invoked','--address','2'.repeat(95),'--contact','Local rehearsal only'];
 const stdout=execFileSync(process.execPath,args,{timeout:10000,windowsHide:true,encoding:'utf8'});
 const config=JSON.parse(readFileSync(configPath));assert(!stdout.includes(config.sessions[0].token));
 assert.equal(config.experiment.endsUtcUnix-config.experiment.startsUtcUnix,5);
 const before=readFileSync(configPath);
 assert.throws(()=>execFileSync(process.execPath,args,{timeout:10000,windowsHide:true,stdio:'ignore'}));assert.deepEqual(readFileSync(configPath),before);
 const child=spawn(process.execPath,[fileURLToPath(new URL('../testnet_service.mjs',import.meta.url)),configPath],{stdio:['ignore','pipe','pipe']});
 let text='';child.stdout.on('data',x=>text+=x);child.stderr.on('data',x=>text+=x);
 const result=await new Promise((ok,bad)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');bad(Error('Epoch CLI did not close'));},8000);child.once('close',code=>{clearTimeout(timer);ok(code);});});
 assert.equal(result,0,text);assert(text.includes('"listening"'));assert(!text.includes(config.sessions[0].token));
 try{execFileSync(process.execPath,[fileURLToPath(new URL('../testnet_service.mjs',import.meta.url)),configPath],{timeout:5000,windowsHide:true,stdio:'pipe'});assert.fail('Expired restart listened');}
 catch(error){assert.notEqual(error.status,0);assert.match(String(error.stderr),/experiment not active/);assert(!String(error.stdout).includes('"listening"'));}
 const badArgs=[...args];badArgs[badArgs.indexOf('--out')+1]=join(dir,'wrong-origin.json');badArgs[badArgs.indexOf('--origin')+1]='https://wrong.invalid';
 assert.throws(()=>execFileSync(process.execPath,badArgs,{timeout:10000,windowsHide:true,stdio:'ignore'}));assert(!existsSync(join(dir,'wrong-origin.json')));
});
test('Sessions receive distinct nonce ranges and direct configured reward addresses',async t=>{
 const f=await fixture(t);
 const a=await f.request('/api/start',{method:'POST',data:{}});
 const b=await f.request('/api/start',{token:tokenB,method:'POST',data:{}});
 assert.equal(a.status,200);assert.equal(b.status,200);
 assert.notEqual(a.json().nonceStart,b.json().nonceStart);
 const statusA=(await f.request('/api/status')).json(),statusB=(await f.request('/api/status',{token:tokenB})).json();
 assert.equal(statusA.payoutAddress,'2'.repeat(95));assert.equal(statusB.payoutAddress,'3'.repeat(95));
});
test('Disk and daemon outage stop admission; healthy recovery does not need a service restart',async t=>{
 const f=await fixture(t);
 f.space(100n);assert.equal((await f.request('/api/start',{method:'POST',data:{}})).status,503);
 f.space(2n*1024n**3n);f.available(false);
 assert.equal((await f.request('/readyz')).status,503);
 assert.equal((await f.request('/api/start',{method:'POST',data:{}})).status,503);
 f.available(true);assert.equal((await f.request('/api/start',{method:'POST',data:{}})).status,200);
});
test('Rotation stops active work, invalidates old capability and preserves attempt budgets',async t=>{
 const f=await fixture(t,{maxJobs:1});
 assert.equal((await f.request('/api/start',{method:'POST',data:{}})).status,200);
 const next=await f.service.rotate(tokenA);assert.match(next,/^[a-f0-9]{64}$/);
 assert.equal((await f.request('/api/status')).status,403);
 assert.equal((await f.request('/api/status',{token:next})).json().running,false);
 assert.equal((await f.request('/api/start',{token:next,method:'POST',data:{}})).status,409);
});
test('Request, body and expiry limits fail closed without resetting another session budget',async t=>{
 const f=await fixture(t,{requestsPerMinute:3,sessionTtlMs:1000});
 assert.equal((await f.request('/api/start',{method:'POST',data:{x:'x'.repeat(3000)}})).status,413);
 assert.equal((await f.request('/api/start',{method:'POST',data:{forged:true}})).status,400);
 assert.equal((await f.request('/api/status')).status,200);
 assert.equal((await f.request('/api/status')).status,429);
 assert.equal((await f.request('/api/status',{token:tokenB})).status,200);
 f.clock(1001);assert.equal((await f.request('/api/status',{token:tokenB})).status,403);
});
test('Service rejects cleartext advertised origins and duplicate capabilities before opening listeners',async()=>{
 const options={tls,origin:'http://localhost',expectedGenesisHash:'c'.repeat(64),expectedVersion:'fixture-build',sessions:[{token:tokenA,walletAddress:'2'.repeat(95)}]};
 await assert.rejects(createTestnetService(options),/HTTPS/);
 await assert.rejects(createTestnetService({...options,origin:'https://localhost',sessions:[options.sessions[0],options.sessions[0]]}),/unique/);
});

test('Wrong daemon network, version or genesis refuses mining admission',async t=>{
 const f=await fixture(t);
 for(const identity of [{nettype:'mainnet'},{nettype:'testnet',version:'different-build'},
  {version:'fixture-build',genesis:'d'.repeat(64)}]){
  f.identity(identity);const r=await f.request('/api/start',{method:'POST',data:{}});
  assert.equal(r.status,503);assert.equal(r.json().error,'daemon_identity');
 }
 f.identity({genesis:'c'.repeat(64)});assert.equal((await f.request('/readyz')).status,200);
});

test('Rotation while health is pending rejects the old start before gateway admission',async t=>{
 const f=await fixture(t),gate=f.holdHealth();
 const pending=f.request('/api/start',{method:'POST',data:{}});await gate.reached;
 const next=await f.service.rotate(tokenA);gate.release();
 assert.equal((await pending).status,403);
 const status=(await f.request('/api/status',{token:next})).json();
 assert.equal(status.running,false);assert.equal(status.attemptedStarts,0);
 assert.equal((await f.request('/api/start',{token:next,method:'POST',data:{}})).status,200);
});

test('An operator revoke or shutdown wins a simultaneous rotation',async t=>{
 const f=await fixture(t);
 const rotating=f.service.rotate(tokenA),revoking=f.service.revoke(tokenA);
 await revoking;await assert.rejects(rotating,/rotation_cancelled/);
 assert.equal((await f.request('/api/status')).status,403);
 const another=await fixture(t);
 const pending=another.service.rotate(tokenA),closed=another.service.close();
 await closed;await assert.rejects(pending,/rotation_cancelled/);
 await assert.rejects(another.service.rotate(tokenB),/closing/);
});

test('Delayed health cannot reopen cached readiness after operator shutdown',async t=>{
 const f=await fixture(t);assert.equal((await f.service.checkReady()).ready,true);
 const gate=f.holdHealth(),pending=f.service.checkReady();await gate.reached;
 await f.service.close();assert.equal(f.service.readiness().ready,false);
 gate.release();assert.deepEqual(await pending,{ready:false,reason:'closing'});
 assert.deepEqual(f.service.readiness(),{ready:false,reason:'closing'});
});

test('Expiry actively cancels a live gateway without waiting for another client request',async t=>{
 const gateways=[];const f=await fixture(t,{sessionTtlMs:1000,gatewayFactory:async options=>{
  const gateway=await createPrivateGateway({...options,nativeFactory:()=>({hashOne:()=>{throw Error('unexpected');}})});gateways.push(gateway);return gateway;
 }});
 assert.equal((await f.request('/api/start',{method:'POST',data:{}})).status,200);
 assert.equal(gateways[0].snapshot().running,true);f.clock(1001);
 const until=Date.now()+2500;while(gateways[0].snapshot().running&&Date.now()<until)await new Promise(ok=>setTimeout(ok,20));
 assert.equal(gateways[0].snapshot().running,false);
});


test('Disconnected candidate retains the single native verifier slot until processing settles',async t=>{
 let release,entered;const gate=new Promise(ok=>release=ok),reached=new Promise(ok=>entered=ok);
 let calls=0,active=0,peak=0;
 const f=await fixture(t,{gatewayFactory:options=>createPrivateGateway({...options,nativeFactory:()=>({hashOne:async()=>{
  calls++;active++;peak=Math.max(peak,active);
  try{if(calls===1){entered();await gate;}return new Uint8Array(32);}finally{active--;}
 }})})});
 t.after(()=>release());
 const a=(await f.request('/api/start',{method:'POST',data:{}})).json();
 const b=(await f.request('/api/start',{method:'POST',data:{},token:tokenB})).json();
 const candidate=job=>({jobId:job.jobId,issuanceId:job.issuanceId,nonce:job.nonceStart,runGeneration:job.runGeneration,workerId:job.workerId});
 const abort=new AbortController();
 const first=f.request('/api/candidate',{method:'POST',data:candidate(a),signal:abort.signal}).catch(error=>error);
 await reached;abort.abort();await first;
 await new Promise(ok=>setTimeout(ok,50));
 assert.equal((await f.request('/api/candidate',{method:'POST',data:candidate(b),token:tokenB})).status,429);
 assert.equal(calls,1);assert.equal(active,1);release();
 let next;const deadline=Date.now()+2000;
 do{next=await f.request('/api/candidate',{method:'POST',data:candidate(b),token:tokenB});if(next.status===429)await new Promise(ok=>setTimeout(ok,20));}while(next.status===429&&Date.now()<deadline);
 assert.equal(next.status,200);assert.equal(calls,2);assert.equal(peak,1);
});
