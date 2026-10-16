// A 60-second real-browser workload using the shipped Worker and its 100ms pacing.
// No node, native submission, personal profile or public mining is involved.
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const arg=name=>process.argv[process.argv.indexOf('--'+name)+1];
const product=fileURLToPath(new URL('../../',import.meta.url));
const root=resolve(arg('run-dir'));await mkdir(root,{mode:0o700});
const {chromium}=await import(pathToFileURL(resolve(arg('playwright-module'))));
const vector=JSON.parse(await readFile(resolve(product,'meepow/vectors/block_vectors_v16_devnet.json'),'utf8')).vectors[1];
const {ROUTES}=await import(new URL('../../pool/dev/static.mjs',import.meta.url));
const allowed=new Map();
for(const [route,descriptor] of Object.entries(ROUTES)) {
  if(route==='/worker.js'||route.startsWith('/lib/')||route.startsWith('/wasm/')) {
    allowed.set(route,descriptor);
  }
}
let server,browser,context;
try {
 server=http.createServer(async(req,res)=>{
  try {
   if(req.url==='/'){res.setHeader('Content-Type','text/html');return res.end('<!doctype html><title>MeepCoin finite throughput</title><p>Private 60-second qualification</p>');}
   const entry=allowed.get(req.url);if(!entry){res.writeHead(404);return res.end();}
   res.setHeader('Content-Type',entry.type);res.end(await readFile(entry.file));
  }catch{res.writeHead(500);res.end();}
 });
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 browser=await chromium.launch({executablePath:arg('browser'),headless:true,chromiumSandbox:true,
   args:['--no-first-run','--disable-background-networking','--disable-component-update','--disable-sync']});
 context=await browser.newContext();const page=await context.newPage();
 await page.goto('http://127.0.0.1:'+server.address().port);
 const result=await page.evaluate(async vector=>{
  const worker=new Worker('/worker.js',{type:'module'});let hashes=0,start,ready;const samples=[];
  try {
   return await new Promise((ok,bad)=>{
    const timer=setTimeout(()=>{worker.terminate();bad(Error('throughput deadline'));},90000);
    worker.onerror=e=>{clearTimeout(timer);bad(Error(e.message));};
    worker.onmessage=({data:m})=>{
     if(m.ev==='ready'){ready=performance.now();start=ready;worker.postMessage({cmd:'search',gen:1,jobId:'throughput'});}
     if(m.ev==='progress'){hashes=m.hashes;samples.push({elapsedMs:performance.now()-start,hashes});}
     if(m.ev==='error'||m.ev==='command_refused'){clearTimeout(timer);bad(Error(JSON.stringify(m)));}
     if(m.ev==='finished'){clearTimeout(timer);ok({hashes:m.hashes,elapsedMs:performance.now()-start,found:m.found,samples,userAgent:navigator.userAgent,hidden:document.hidden});}
    };
    worker.postMessage({cmd:'init_search',gen:1,jobId:'throughput',sequenceTotal:1,pacingMs:100,
     context:{epochKeyHex:vector.epoch_key,seedHashHex:vector.epoch_key,height:String(vector.height),hashingTemplateHex:vector.block_hashing_blob},
     window:{nonceStart:0,nonceRange:8192,maxSearchMs:60000,targetHexLE:'00'.repeat(32)}});
   });
  }finally{worker.terminate();}
 },vector);
 assert(!result.found&&result.elapsedMs>=59000&&result.elapsedMs<85000&&result.hashes>0);
 const wasm=await readFile(resolve(product,'meepow/wasm/meepow.wasm'));
 await writeFile(resolve(root,'RESULT.json'),JSON.stringify({status:'REAL_BROWSER_60_SECOND_PACED_THROUGHPUT_PASS',...result,
  hashesPerSecond:result.hashes/(result.elapsedMs/1000),wasmSha256:createHash('sha256').update(wasm).digest('hex'),
  limits:['One actual Worker, 100ms production pacing, fixed known context, headless sandboxed desktop browser',
   'No block submitted; variable real templates, network latency, thermal and adverse participation not qualified']},null,2)+'\n',{flag:'wx'});
 console.log('REAL_BROWSER_60_SECOND_PACED_THROUGHPUT_PASS');
}finally{await context?.close();await browser?.close();if(server)await new Promise(ok=>server.close(ok));}
