// Invite-only, direct solo mining. No wallet keys, public daemon RPC, or payout ledger.
import https from 'node:https';
import http from 'node:http';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {readFile,statfs,lstat,open,rename,writeFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
import {createPrivateGateway} from './server.mjs';
import {ROUTES} from '../dev/static.mjs';
import {experimentWindow} from './experiment.mjs';
import {validateTlsIdentity} from './tls_identity.mjs';
import {progressPolicy} from './availability.mjs';

const fail=(code,status=400)=>Object.assign(new Error(code),{code,status});
const validToken=x=>typeof x==='string' && /^[a-f0-9]{64}$/.test(x);
export async function createTestnetService({
  endpoint,nativeCommand,tls,origin,host='127.0.0.1',port=0,sessions,
  dataDirectory,minFreeBytes=1024**3,sessionTtlMs=3600000,maxJobs=32,
  expectedNetwork='testnet',expectedGenesisHash,expectedVersion,
  requestsPerMinute=120,startsPerMinute=6,now=()=>performance.now(),
  experiment,incidentContact,wallNow=Date.now,
  availabilityFile,
  gatewayFactory=createPrivateGateway,freeBytes=async()=>{const s=await statfs(dataDirectory,{bigint:true});return s.bavail*s.bsize;},
}={}) {
  const advertised=new URL(origin);
  if(advertised.protocol!=='https:' || advertised.origin!==origin || advertised.username || advertised.password)
    throw new TypeError('exact HTTPS origin required');
  if(!tls?.key || !tls?.cert)throw new TypeError('TLS key and certificate required');
  if(!['testnet','fakechain'].includes(expectedNetwork)||!/^[a-f0-9]{64}$/.test(expectedGenesisHash??'')||typeof expectedVersion!=='string'||!expectedVersion.length)
    throw new TypeError('explicit test network, genesis hash and exact daemon version required');
  if(!Array.isArray(sessions) || sessions.length<1 || sessions.length>8)throw new TypeError('1..8 invite sessions required');
  if(!Number.isSafeInteger(sessionTtlMs)||sessionTtlMs<1000||sessionTtlMs>86400000)throw new TypeError('session lifetime 1 second..24 hours');
  for(const [name,value,max] of [['minFreeBytes',minFreeBytes,Number.MAX_SAFE_INTEGER],['requestsPerMinute',requestsPerMinute,600],['startsPerMinute',startsPerMinute,32]])
    if(!Number.isSafeInteger(value)||value<1||value>max)throw new TypeError(name+' out of range');
  if(new Set(sessions.map(s=>s.token)).size!==sessions.length || sessions.some(s=>!validToken(s.token)))
    throw new TypeError('unique 256-bit invitation tokens required');
  const epoch=experiment===undefined?null:experimentWindow(experiment,wallNow,now);
  if(epoch&&(typeof incidentContact!=='string'||!incidentContact.trim()||incidentContact.length>200||/[\r\n\x00-\x1f]/.test(incidentContact)))
    throw new TypeError('plain incident contact required');
  const epochOpen=()=>!epoch||epoch.open();
  let progress,savedProgress;
  if(epoch){
    if(typeof availabilityFile!=='string'||!availabilityFile.length)throw TypeError('Persisted progress file required for a finite epoch');
    let restored;
    if(availabilityFile){
      const meta=await lstat(availabilityFile);
      if(!meta.isFile()||meta.isSymbolicLink()||(process.platform!=='win32'&&(meta.uid!==process.getuid()||meta.mode&0o077)))
        throw TypeError('Private owned progress file required');
      restored=JSON.parse(await readFile(availabilityFile,'utf8'));
      savedProgress=JSON.stringify(restored);
    }
    progress=progressPolicy({genesis:expectedGenesisHash,startedUtcUnix:experiment.startsUtcUnix,restored,wallNow,monotonicNow:now});
  }
  let closing=false,closeTask,nonceCursor=0,candidateBusy=false,nativeCandidateBusy=false,startBusy=false;
  const records=[];const sockets=new Set();const addresses=new Map();const anonymousRequests=[];const staticClients=new Map();
  let readiness={ready:false,reason:'starting'};
  const allocateNonceRange=()=>{if(nonceCursor+8192>0x100000000)throw fail('nonce_space_exhausted',409);const n=nonceCursor;nonceCursor+=8192;return n;};
  try {
    for(const session of sessions) {
      const record={token:session.token,expires:Math.min(now()+sessionTtlMs,epoch?.deadline??Infinity),revoked:false,revision:0,requests:[],starts:[],inFlight:0};
      record.gateway=await gatewayFactory({endpoint,nativeCommand,walletAddress:session.walletAddress,maxJobs,allocateNonceRange,
        acquireCandidate:()=>{
          if(nativeCandidateBusy)return null;nativeCandidateBusy=true;
          let released=false;return ()=>{if(!released){released=true;nativeCandidateBusy=false;}};
        },
        authorizeStart:revision=>!closing&&epochOpen()&&!record.revoked&&now()<record.expires&&revision===String(record.revision)});
      records.push(record);
    }
  }catch(e){await Promise.allSettled(records.map(r=>r.gateway.close()));throw e;}
  function lookup(token) {
    if(!epochOpen()||!validToken(token))return null;
    return records.find(r=>timingSafeEqual(Buffer.from(token,'hex'),Buffer.from(r.token,'hex'))&&!r.revoked&&now()<r.expires)??null;
  }
  function quota(times,limit) {
    const time=now();while(times.length && times[0]<=time-60000)times.shift();
    if(times.length>=limit)throw fail('rate_limit',429);times.push(time);
  }
  let healthTask;
  function checkReady(){
    if(!healthTask)healthTask=readinessCheck().finally(()=>{healthTask=undefined;});
    return healthTask;
  }
  async function persistProgress(observed){
    if(!availabilityFile||!observed)return;
    const {lastBlockAgeSeconds,stallAfterSeconds,...state}=observed;
    const serialized=JSON.stringify(state);
    if(serialized===savedProgress)return;
    const temporary=availabilityFile+'.'+randomBytes(8).toString('hex')+'.pending';
    const file=await open(temporary,'wx',0o600);
    try{await file.writeFile(serialized+'\n');await file.sync();}finally{await file.close();}
    await rename(temporary,availabilityFile);
    if(process.platform!=='win32'){
      const directory=await open(dirname(availabilityFile),'r');
      try{await directory.sync();}finally{await directory.close();}
    }
    savedProgress=serialized;
  }
  async function readinessCheck() {
    try {
      if(closing)return readiness={ready:false,reason:'closing'};
      if(!epochOpen())return readiness={ready:false,reason:'experiment_expired'};
      const initial=progress?.snapshot();
      if(initial?.closed){await persistProgress(initial);return readiness={ready:false,...initial};}
      if(BigInt(await freeBytes())<BigInt(minFreeBytes))return readiness={ready:false,reason:'disk_space'};
      const signal=AbortSignal.timeout(3000);
      async function healthRpc(method,params={}) {
      const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({jsonrpc:'2.0',id:'health',method,params}),signal});
      // Bound daemon responses as strictly as client responses; do not buffer an arbitrary body.
      const reader=response.body.getReader();let bytes=0,chunks=[];
      for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.length;if(bytes>65536){await reader.cancel();throw Error('daemon response too large');}chunks.push(value);}
      const data=JSON.parse(Buffer.concat(chunks).toString());
      if(!response.ok||data.error)throw Error('daemon not ready');return data.result;
      }
      const r=await healthRpc('get_info');
      if(!r||r.status!=='OK'||!Number.isSafeInteger(r.height)||r.height<1)
        throw Error('daemon not ready');
      if(r.nettype!==expectedNetwork||r.version!==expectedVersion)return readiness={ready:false,reason:'daemon_identity'};
      const genesis=await healthRpc('get_block_header_by_height',{height:0});
      if(genesis?.status!=='OK'||genesis.block_header?.hash!==expectedGenesisHash)return readiness={ready:false,reason:'daemon_identity'};
      if(epoch&&genesis.block_header.timestamp!==epoch.genesisUtcUnix)return readiness={ready:false,reason:'daemon_identity'};
      const observed=progress?.observe(r.height,r.top_block_hash);
      await persistProgress(observed);
      if(observed?.closed)return readiness={ready:false,reason:observed.reason,...observed};
      if(closing)return readiness={ready:false,reason:'closing'};
      if(!epochOpen())return readiness={ready:false,reason:'experiment_expired'};
      return readiness={ready:true,reason:'ready',height:r.height,
        ...(observed?{lastBlockAgeSeconds:observed.lastBlockAgeSeconds,stallAfterSeconds:observed.stallAfterSeconds}: {})};
    }catch(error){
      if(error?.code&&['ENOSPC','EDQUOT','EIO','EROFS','EACCES'].includes(error.code))progress?.close('progress_storage_failed');
      return readiness={ready:false,reason:closing?'closing':'daemon_unavailable'};
    }
  }
  function upstream(record,path,method,body,signal) {
    return new Promise((ok,bad)=>{
      const u=new URL(record.gateway.origin);
      const request=http.request({hostname:u.hostname,port:u.port,path,method,agent:false,signal,headers:{
        Host:u.host,Origin:u.origin,'X-Meep-Session':record.gateway.sessionToken,'X-Meep-Revision':String(record.revision),
        ...(body?{'Content-Type':'application/json','Content-Length':body.length}:{}),
      }},response=>{
        let bytes=0,chunks=[];response.on('data',chunk=>{bytes+=chunk.length;if(bytes>2*1024**2)request.destroy(Error('upstream response limit'));else chunks.push(chunk);});
        response.on('error',bad);response.on('end',()=>ok({status:response.statusCode,headers:response.headers,body:Buffer.concat(chunks)}));
      });
      request.on('error',bad);request.setTimeout(15000,()=>request.destroy(Error('upstream timeout')));
      request.end(body);
    });
  }
  // A module Worker fetches several imports in parallel. Snapshot the closed public
  // route set before listening, rather than rejecting ordinary import bursts while
  // proxy I/O is pending. Wasm bytes come from the gateway's verified snapshots.
  const staticAssets=new Map();let staticBytes=0;
  try {
    const paths=['/','/private/app.js','/private/style.css',...Object.keys(ROUTES).filter(p=>p==='/worker.js'||p.startsWith('/lib/')||p.startsWith('/wasm/'))];
    for(const path of paths){
      const asset=await upstream(records[0],path,'GET');
      if(asset.status!==200)throw Error('static asset unavailable');
      staticBytes+=asset.body.length;if(staticBytes>8*1024**2)throw Error('static snapshot limit');
      staticAssets.set(path,asset);
    }
  }catch(error){await Promise.allSettled(records.map(r=>r.gateway.close()));throw error;}
  if(!epochOpen()){await Promise.allSettled(records.map(r=>r.gateway.close()));throw fail('experiment_expired',503);}
  async function revoke(record,reason) {
    record.revoked=true;const revision=++record.revision;
    // Revocation stops active work even when no further browser request arrives.
    await record.gateway.cancel();
    return revision;
  }
  const server=https.createServer({...tls,minVersion:'TLSv1.2',handshakeTimeout:5000},async(req,res)=>{
    let record,revision,admissionToken,admitted=false,claimedCandidate=false,claimedStart=false;
    const disconnected=new AbortController();
    res.once('close',()=>{
      if(res.writableEnded)return;
      disconnected.abort();
      if(admitted&&record.revision===revision&&record.token===admissionToken){
        // A lost HTTP response invalidates the outstanding work, not the
        // owner's invitation. Explicit revoke/expiry still close authorization.
        // Increment before cancellation so delayed replies cannot issue a job.
        record.revision++;
        void record.gateway.cancel();
      }
    });
    const send=(status,body,headers={})=>{
      if(res.destroyed)return;
      if(res.headersSent){res.destroy();return;}
      const bytes=Buffer.isBuffer(body)?body:Buffer.from(JSON.stringify(body));
      res.writeHead(status,{'content-type':'application/json',...headers,'content-length':bytes.length,
        'cache-control':'no-store','referrer-policy':'no-referrer','strict-transport-security':'max-age=31536000',
        'x-content-type-options':'nosniff'});res.end(bytes);
    };
    try {
      if(closing)throw fail('closing',503);
      if(req.headers.host!==advertised.host)throw fail('bad_host',403);
      if(!req.url.startsWith('/')||req.url.startsWith('//')||req.url.includes('?'))throw fail('bad_path');
      const path=new URL(req.url,origin).pathname;
      if(path==='/healthz'&&req.method==='GET')return send(200,{alive:true});
      if(path.startsWith('/api/')||path==='/readyz') {
        record=lookup(req.headers['x-meep-session']);if(!record)throw fail('unauthorized',403);
        if(record.inFlight>=3)throw fail('client_busy',429);
        quota(record.requests,requestsPerMinute);record.inFlight++;admitted=true;revision=record.revision;admissionToken=req.headers['x-meep-session'];
        if(path==='/readyz'){
          const ready=await checkReady();
          if(disconnected.signal.aborted||closing||record.revision!==revision||!lookup(admissionToken))throw fail('unauthorized',403);
          return send(ready.ready?200:503,ready);
        }
        if(!['/api/status','/api/start','/api/stop','/api/candidate'].includes(path))throw fail('not_found',404);
        if(req.method!==(path==='/api/status'?'GET':'POST'))throw fail('method',405);
        if(req.method!=='GET'&&req.headers.origin!==origin)throw fail('bad_origin',403);
        let body;
        if(req.method!=='GET') {
          if(req.headers['content-type']!=='application/json')throw fail('json_required',415);
          if(Number(req.headers['content-length']??0)>2048)throw fail('body_too_large',413);
          let size=0,chunks=[];
          for await(const chunk of req){size+=chunk.length;if(size>2048)throw fail('body_too_large',413);chunks.push(chunk);}
          body=Buffer.concat(chunks);
        }
        if(closing||!lookup(req.headers['x-meep-session']))throw fail('unauthorized',403);
        if(path==='/api/start') {
          quota(record.starts,startsPerMinute);
          if(startBusy)throw fail('server_busy',429);
          startBusy=true;claimedStart=true;
          if(!(await checkReady()).ready)throw fail(readiness.reason,503);
          if(disconnected.signal.aborted||closing||record.revision!==revision||!lookup(admissionToken))throw fail('unauthorized',403);
        }
        if(path==='/api/candidate') {
          if(candidateBusy||nativeCandidateBusy)throw fail('server_busy',429);
          candidateBusy=true;claimedCandidate=true;
        }
        const response=await upstream(record,path,req.method,body,disconnected.signal);
        // A response obtained after revocation must not hand a live job to the browser.
        if(record.revision!==revision||!lookup(admissionToken)){
          if(record.revision===revision)await revoke(record,'expired');
          throw fail('unauthorized',403);
        }
        if(path==='/api/status'&&response.status===200){
          const status=JSON.parse(response.body.toString());
          const availability=await checkReady();
          if(disconnected.signal.aborted||closing||record.revision!==revision||!lookup(admissionToken))throw fail('unauthorized',403);
          return send(200,{...status,availability});
        }
        return send(response.status,response.body);
      }
      if(req.method!=='GET')throw fail('method',405);
      quota(anonymousRequests,1200);
      const ip=req.socket.remoteAddress;
      const time=now();
      for(const [address,entry] of staticClients)if(entry.at<=time-60000)staticClients.delete(address);
      let entry=staticClients.get(ip);
      if(!entry){entry={at:time,requests:[]};staticClients.set(ip,entry);}
      quota(entry.requests,240);entry.at=time;
      const response=staticAssets.get(path);
      if(!response)throw fail('not_found',404);
      let bytes=response.body;
      if(path==='/')bytes=Buffer.from(bytes.toString().replaceAll('Private miner','Testnet miner').replaceAll('MEEP COIN / PRIVATE LAB','MEEP COIN / TESTNET')
        .replace('This page connects to your private node.','This invitation connects to an experimental testnet node.')
        .replace('Private experimental build · No public network connections from this page','Experimental testnet · Test coins have no monetary value'));
      if(path==='/'&&epoch){
        const escape=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
        const notice='<section class="notes"><h2>Experiment notice</h2><p>This experiment ends at '+new Date(experiment.endsUtcUnix*1000).toISOString()
          +'. The operator may stop it earlier. A reset starts a new chain; balances are not promised to survive.</p><p>No miners means no new blocks. Block time, reward maturity and payments may stall. Ten minutes without canonical progress closes new mining admission for this experiment.</p><p>Incident contact: '+escape(incidentContact)+'</p></section>';
        bytes=Buffer.from(bytes.toString().replace('</main>',notice+'</main>'));
      }
      const headers=Object.fromEntries(Object.entries(response.headers).filter(([k])=>!['connection','keep-alive','content-length','transfer-encoding'].includes(k)));
      return send(response.status,bytes,headers);
    }catch(e){send(e.status??502,{error:e.code??'service_unavailable'});}
    finally {
      if(admitted)record.inFlight--;
      if(claimedCandidate)candidateBusy=false;if(claimedStart)startBusy=false;
    }
  });
  server.maxConnections=32;server.maxHeadersCount=32;server.requestTimeout=10000;server.headersTimeout=10000;
  server.setTimeout(25000,socket=>socket.destroy());server.keepAliveTimeout=2000;
  server.on('connection',socket=>{
    const ip=socket.remoteAddress;const count=addresses.get(ip)??0;
    if(count>=8){socket.destroy();return;}addresses.set(ip,count+1);
    sockets.add(socket);socket.once('close',()=>{sockets.delete(socket);const n=(addresses.get(ip)??1)-1;if(n)addresses.set(ip,n);else addresses.delete(ip);});
  });
  const expiry=setInterval(()=>{
    if(!epochOpen()){void close();return;}
    for(const r of records)if(!r.revoked&&now()>=r.expires)void revoke(r,'expired');
  },1000);expiry.unref();
  let healthBusy=false;
  const health=setInterval(async()=>{
    if(healthBusy||closing)return;healthBusy=true;
    try {
      if(!(await checkReady()).ready)await Promise.allSettled(records.map(r=>r.gateway.cancel()));
    }finally{healthBusy=false;}
  },2000);health.unref();
  const endTimer=epoch?setTimeout(()=>void close(),Math.max(1,epoch.deadline-now())):null;endTimer?.unref();
  try {await new Promise((ok,bad)=>{server.once('error',bad);server.listen(port,host,ok);});}
  catch(e){clearInterval(expiry);clearInterval(health);clearTimeout(endTimer);await Promise.allSettled(records.map(r=>r.gateway.close()));throw e;}
  if(!epochOpen()){await close();throw fail('experiment_expired',503);}
  return {port:server.address().port,readiness:()=>closing?{ready:false,reason:'closing'}:!epochOpen()?{ready:false,reason:'experiment_expired'}:{...readiness},checkReady,
    async rotate(token) {
      if(closing)throw fail('closing',503);
      const r=lookup(token);if(!r)throw fail('unauthorized',403);
      const revision=await revoke(r,'rotated');
      if(closing||!epochOpen()||r.revision!==revision)throw fail('rotation_cancelled',409);
      r.token=randomBytes(32).toString('hex');r.expires=Math.min(now()+sessionTtlMs,epoch?.deadline??Infinity);r.revoked=false;
      // Preserve all attempt/rate budgets on rotation.
      return r.token;
    },
    revoke:async token=>{const r=validToken(token)&&records.find(r=>timingSafeEqual(Buffer.from(token,'hex'),Buffer.from(r.token,'hex')));if(r)await revoke(r,'operator_revoked');},
    close};
    function close() {
      if(closeTask)return closeTask;closing=true;readiness={ready:false,reason:'closing'};clearInterval(expiry);clearInterval(health);clearTimeout(endTimer);
      closeTask=(async()=>{
        const closed=new Promise(ok=>server.close(ok));
        for(const socket of sockets)socket.destroy();
        await Promise.allSettled(records.map(r=>revoke(r,'shutdown')));
        await Promise.allSettled(records.map(r=>r.gateway.close()));
        await closed;
      })();return closeTask;
    }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  async function ownerFile(path) {
    const s=await lstat(path);
    if(!s.isFile()||s.isSymbolicLink()||(process.platform!=='win32'&&((s.mode&0o077)!==0||s.uid!==process.getuid())))
      throw Error('owner-only regular secret file required');
  }
  await ownerFile(process.argv[2]);
  const config=JSON.parse(await readFile(process.argv[2],'utf8'));
  if(!config.experiment)throw Error('persisted experiment required; regenerate operator configuration');
  await ownerFile(config.keyFile);
  config.tls={key:await readFile(config.keyFile),cert:await readFile(config.certFile)};
  await validateTlsIdentity({...config.tls,origin:config.origin,endsUtcUnix:config.experiment.endsUtcUnix});
  const service=await createTestnetService(config);
  // Invitations and keys are never printed.
  console.log(JSON.stringify({type:'listening',origin:config.origin,port:service.port}));
  let rotating=false;
  async function replaceSecret(path,object) {
    await ownerFile(path);
    const temporary=path+'.'+randomBytes(8).toString('hex')+'.tmp';
    const file=await open(temporary,'wx',0o600);
    try{await file.writeFile(JSON.stringify(object,null,2)+'\n');await file.sync();}finally{await file.close();}
    await rename(temporary,path);
    const directory=await open(dirname(path),'r');
    try{await directory.sync();}finally{await directory.close();}
  }
  if(config.inviteOutput&&process.platform!=='win32')process.on('SIGHUP',async()=>{
    if(rotating)return;rotating=true;
    try {
      await ownerFile(config.inviteOutput);
      for(const session of config.sessions)session.token=await service.rotate(session.token);
      const output={origin:config.origin,sessions:config.sessions.map(s=>({walletAddress:s.walletAddress,url:config.origin+'/#session='+s.token}))};
      const {tls:runtimeTls,...persistent}=config;
      await replaceSecret(process.argv[2],persistent);await replaceSecret(config.inviteOutput,output);
      console.log(JSON.stringify({type:'invitations_rotated'}));
    }catch {
      // A partial rotation must not strand live, undistributed credentials.
      await service.close();process.exitCode=1;console.error('invitation_rotation_failed_service_closed');
    }finally{rotating=false;}
  });
  for(const sig of ['SIGINT','SIGTERM'])process.once(sig,async()=>{await service.close();});
}
