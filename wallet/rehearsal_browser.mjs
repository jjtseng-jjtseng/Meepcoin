// Device-local, finite UI rehearsal. Secrets remain in this process and the
// encrypted native wallet. Command/receipt files contain public values only.
import assert from 'node:assert/strict';
import {readFile,writeFile,readdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes} from 'node:crypto';
const arg=n=>{const i=process.argv.indexOf('--'+n);assert(i>=0,'Missing '+n);return process.argv[i+1];};
const root=resolve(arg('output')),data=resolve(arg('data'));
const {chromium}=await import(pathToFileURL(resolve(arg('playwright-module'))));
const pause=ms=>new Promise(ok=>setTimeout(ok,ms));
const save=(n,v)=>writeFile(join(root,n),JSON.stringify(v,null,2)+'\n',{flag:'wx',mode:0o600});
const password=randomBytes(32).toString('hex');let seed='',browser,context,page,miner,closing=false;
const pageErrors=[];let commandFailures=0;let walletName=process.argv.includes('--wallet-name')?arg('wallet-name'):'rehearsal-original',address='';
const originalWalletName=walletName;
assert(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,35}$/.test(walletName),'Invalid isolated rehearsal wallet name');
const atomic=text=>{const [a,b='']=text.trim().replace(/ MEEP$/,'').split('.');assert(/^\d+$/.test(a)&&/^\d{0,11}$/.test(b));return(BigInt(a)*100000000000n+BigInt(b.padEnd(11,'0'))).toString();};
const scrub=error=>{let t=String(error?.message??error);for(const secret of [password,seed])if(secret)t=t.split(secret).join('[private value]');return t.replace(/#(?:session|connect)=[^\s\"'<>)]*/gi,'#[private capability]').slice(0,2000);};
async function cleanup(reason){
 if(closing)return;closing=true;
 const errors=[];
 for(const close of [()=>context?.close(),()=>browser?.close()]){
  let timer;try{await Promise.race([close(),new Promise((_,bad)=>{timer=setTimeout(()=>bad(Error('Browser disconnect deadline')),5000);})]);}
  catch(error){errors.push(scrub(error));}finally{clearTimeout(timer);}
 }
 seed='';await save('BROWSER_CLEANUP.json',{reason,browserSessionDisconnected:errors.length===0,cleanupErrors:errors,
  nativeBrowserExitProvenBy:'BROWSER_OWNERSHIP_STOPPED.json from parent live-pipe guardian',secretsExported:false}).catch(()=>{});
}
for(const s of ['SIGTERM','SIGINT'])process.on(s,async()=>{await cleanup(s);process.exit(130);});
const deadline=setTimeout(async()=>{await cleanup('finite_deadline');process.exit(124);},4200000);
async function lock(){if(await page.locator('#opened').isVisible()){await page.getByRole('button',{name:'Lock wallet',exact:true}).click();await page.locator('#closed').waitFor({state:'visible'});}}
async function unlock(){
 const hidden=await page.evaluate(()=>document.hidden);
 const refreshed=hidden?page.waitForResponse(r=>new URL(r.url()).pathname==='/api/state'&&r.request().method()==='POST',{timeout:15000}):null;
 await page.bringToFront();
 // A hidden page's DOM can still say "opened" after its native wallet was
 // locked. Await the visibility-triggered state request and settled controls
 // before using that DOM to decide whether the unlock form is necessary.
 if(refreshed){await (await refreshed).finished();await page.waitForFunction(()=>!document.getElementById('refresh').disabled);}
 // A background timer can leave an opened DOM after the native idle deadline.
 // Deliberately settle Lock before opening; never infer key state from stale UI.
 if(await page.locator('#opened').isVisible())await lock();
 await page.getByRole('button',{name:'Unlock',exact:true}).click();
 await page.getByLabel('Wallet name',{exact:true}).fill(walletName);
 await page.getByLabel('Wallet password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Unlock wallet',exact:true}).click();
 await page.locator('#opened').waitFor({state:'visible',timeout:45000});
 assert(await page.locator('#address').textContent()===address);
}
async function snapshot(){
 await unlock();await page.getByRole('button',{name:'Refresh from node',exact:true}).click();
 await page.waitForFunction(()=>!document.getElementById('refresh').disabled&&document.getElementById('notice').textContent==='Balances and transactions refreshed.',null,{timeout:45000});
 const result={address,balanceAtomic:atomic(await page.locator('#balance').textContent()),unlockedAtomic:atomic(await page.locator('#unlocked').textContent()),
  transactions:await page.locator('#transactions tr').evaluateAll(rows=>rows.map(row=>[...row.querySelectorAll('td')].map(td=>td.textContent)))};
 return result;
}
async function openMiner(){
 if(miner&&!miner.isClosed()){await miner.bringToFront();return;}
 const privateConfig=JSON.parse(await readFile(join(root,'MINER_PRIVATE.json'),'utf8'));
 assert(new URL(privateConfig.url).origin==='https://mine.meepcoin.me');
 miner=await context.newPage();miner.on('pageerror',e=>pageErrors.push(scrub(e)));
 await miner.goto(privateConfig.url,{waitUntil:'networkidle',timeout:45000});await miner.bringToFront();
 assert(await miner.evaluate(()=>document.visibilityState)==='visible');
 await miner.waitForFunction(()=>document.getElementById('address').textContent.length>90,null,{timeout:15000});
 assert(await miner.locator('#address').textContent()===address);
}
async function mine(command){
 assert(Number.isInteger(command.count)&&command.count>=1&&command.count<=64);
 await openMiner();const blocks=[],attempts=[];const end=Date.now()+Math.min(command.seconds??1800,2400)*1000;
 while(blocks.length<command.count&&Date.now()<end){
  await miner.bringToFront();assert(await miner.evaluate(()=>document.visibilityState)==='visible');
  await miner.getByRole('button',{name:'Start mining',exact:true}).click({timeout:15000});
  await miner.waitForFunction(()=>!document.getElementById('start').disabled&&window.meepPrivate.workerCount===0,null,{timeout:Math.min(end-Date.now(),180000)});
  const result=await miner.evaluate(()=>({state:document.getElementById('state').textContent,result:document.getElementById('result').textContent,
   hashes:document.getElementById('hashes').textContent,events:window.meepPrivate.events.slice(-4),workers:window.meepPrivate.workerCount}));
  attempts.push(result);
  if(result.state==='Block observed'){
   const receipt=JSON.parse(result.result);assert(receipt.reason==='verified_complete');blocks.push(receipt);
   await save('MINED-'+command.id+'-'+blocks.length+'.json',{commandId:command.id,observedUtc:Date.now(),...receipt});
  }
  else if(!['Run settled','Unable to start','Window searched','Time limit reached'].includes(result.state))throw Error('Mining stopped: '+result.state);
  if(blocks.length<command.count)await pause(Math.max(11000,Math.min(90000,command.intervalMs??11000)));
 }
 assert(blocks.length===command.count,'Finite block target not reached');
 return {blocks,attempts,workerStopped:true,actualPublicHttps:true};
}
async function prepare(command,send){
 await unlock();await page.getByLabel('Recipient’s public testnet address',{exact:true}).fill(command.address);
 await page.getByLabel('Amount in MEEP',{exact:true}).fill(command.amount??'1');
 await page.getByRole('button',{name:'Review transfer',exact:true}).click();
 await page.locator('#review').waitFor({state:'visible',timeout:45000});
 const result={address:await page.locator('#review-address').textContent(),amountAtomic:atomic(await page.locator('#review-amount').textContent()),
  feeAtomic:atomic(await page.locator('#review-fee').textContent()),totalAtomic:atomic(await page.locator('#review-total').textContent())};
 assert(result.address===command.address);assert(BigInt(result.totalAtomic)===BigInt(result.amountAtomic)+BigInt(result.feeAtomic));
 if(!send){await page.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('#review').waitFor({state:'hidden'});return {...result,cancelled:true};}
 await page.getByRole('button',{name:'Confirm and send',exact:true}).click();
 await page.waitForFunction(()=>/^Last send: submitted\. Transaction: [0-9a-f]{64}\./.test(document.getElementById('send-result').textContent)&&!document.getElementById('refresh').disabled,null,{timeout:45000});
 return {...result,txHash:(await page.locator('#send-result').textContent()).match(/[0-9a-f]{64}/)[0],submitted:true};
}
async function containFailedMiner(){
 if(!miner||miner.isClosed())return {workerStopped:true,pageClosed:true};
 try{
  await miner.bringToFront();await miner.getByRole('button',{name:'Stop',exact:true}).click({timeout:5000});
  assert(await miner.evaluate(()=>window.meepPrivate.workerCount)===0);
  return {workerStopped:true,pageClosed:false};
 }catch{
  await miner.close({runBeforeUnload:false});assert(miner.isClosed());
  return {workerStopped:true,pageClosed:true};
 }
}
async function recover(){
 const before=await snapshot();await lock();
 await page.getByRole('button',{name:'Recover',exact:true}).click();
 const recoveredName=originalWalletName+'-recovered';
 await page.getByLabel('Wallet name',{exact:true}).fill(recoveredName);await page.getByLabel('Wallet password',{exact:true}).fill(password);
 await page.getByLabel('Recovery words',{exact:true}).fill(seed);
 await page.getByRole('button',{name:'Recover into new wallet',exact:true}).click();
 await page.locator('#opened').waitFor({state:'visible',timeout:60000});walletName=recoveredName;
 assert(await page.locator('#address').textContent()===address);assert(await page.locator('#seed-input').inputValue()==='');
 const after=await snapshot();assert(after.balanceAtomic===before.balanceAtomic);
 assert(after.unlockedAtomic===before.unlockedAtomic);
 const canonicalRows=rows=>rows.map(row=>JSON.stringify(row)).sort();
 assert.deepEqual(canonicalRows(after.transactions),canonicalRows(before.transactions),'Recovered canonical history must match at the quiet checkpoint');
 await page.reload({waitUntil:'networkidle'});await page.locator('#closed').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Unlock',exact:true}).click();await page.getByLabel('Wallet name',{exact:true}).fill(walletName);
 await page.getByLabel('Wallet password',{exact:true}).fill('deliberately-incorrect');await page.getByRole('button',{name:'Unlock wallet',exact:true}).click();
 await page.waitForFunction(()=>document.getElementById('notice').classList.contains('error'));assert(await page.locator('#opened').isHidden());
 await unlock();await lock();return {sameAddressAndBalance:true,reloadLocks:true,wrongPasswordRefused:true,recovered:after,secretsExported:false};
}
try{
 const link=await readFile(join(data,'wallets/OPEN_WALLET.html'),'utf8');
 const cdp=JSON.parse(await readFile(resolve(arg('cdp-file')),'utf8'));
 assert(/^http:\/\/127\.0\.0\.1:\d+$/.test(cdp.endpoint));
 browser=await chromium.connectOverCDP(cdp.endpoint,{timeout:15000});context=await browser.newContext({viewport:{width:1200,height:900}});
 page=await context.newPage();page.on('pageerror',e=>pageErrors.push(scrub(e)));await page.goto(link.match(/href="([^"]+)"/)[1],{waitUntil:'networkidle'});
 assert(new URL(page.url()).hash==='');assert((await page.locator('#notice').textContent()).includes('Connected'));
 await page.getByRole('button',{name:'Create',exact:true}).click();await page.getByLabel('Wallet name',{exact:true}).fill(walletName);
 await page.getByLabel('Wallet password',{exact:true}).fill(password);await page.getByRole('button',{name:'Create local wallet',exact:true}).click();
 await page.locator('#backup').waitFor({state:'visible',timeout:45000});seed=await page.locator('#seed-output').textContent();
 assert(seed.trim().split(/\s+/).length>=24);address=await page.locator('#address').textContent();
 await page.getByLabel('I recorded the words in order and can recover this wallet.').check();await page.getByRole('button',{name:'I have backed up my wallet',exact:true}).click();
 await page.locator('#backup').waitFor({state:'hidden'});assert(await page.locator('#seed-output').textContent()==='');await lock();
 await save('CREATED.json',{address,browser:browser.version(),platform:process.platform,encryptedWallet:true,backupConfirmedAndCleared:true,secretsExported:false});
 let previous=0;
 while(!closing){
  let command;try{command=JSON.parse(await readFile(join(root,'COMMAND.json'),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;await pause(200);continue;}
  if(command.id<=previous){await pause(200);continue;}assert(command.id===previous+1,'Command sequence must be consecutive');
  const startedUtc=Date.now();let result;
  try{
   switch(command.action){
    case 'snapshot':result=await snapshot();break;
    case 'mine':result=await mine(command);break;
    case 'cancel':result=await prepare(command,false);break;
    case 'send':result=await prepare(command,true);break;
    case 'recover':result=await recover();break;
    case 'start':await openMiner();await miner.getByRole('button',{name:'Start mining',exact:true}).click();await miner.waitForFunction(()=>window.meepPrivate.workerCount===1||document.getElementById('state').textContent==='Block observed',null,{timeout:15000});result=await miner.evaluate(()=>({workerStarted:window.meepPrivate.workerCount===1,alreadyCompleted:document.getElementById('state').textContent==='Block observed'}));break;
    case 'mining-state':await openMiner();result=await miner.evaluate(()=>({state:document.getElementById('state').textContent,workers:window.meepPrivate.workerCount,hashes:document.getElementById('hashes').textContent}));break;
    case 'stop':await openMiner();await miner.getByRole('button',{name:'Stop',exact:true}).click();assert(await miner.evaluate(()=>window.meepPrivate.workerCount)===0);result={workerStopped:true};break;
    case 'finish':await lock();assert.deepEqual(pageErrors,[]);result={locked:true,pageErrors,priorCommandFailures:commandFailures,secretsExported:false};break;
    default:throw Error('Unsupported finite UI command');
   }
   await save('RESULT-'+command.id+'.json',{status:'PASS',action:command.action,startedUtc,endedUtc:Date.now(),...result});
  }catch(error){
   commandFailures++;
   let containment;
   try{if(['mine','start','stop'].includes(command.action))containment=await containFailedMiner();}
   catch(containmentError){containment={workerStopped:false,error:scrub(containmentError)};}
   const retained=containment?.workerStopped!==false;
   await save('RESULT-'+command.id+'.json',{status:'FAIL',action:command.action,startedUtc,endedUtc:Date.now(),error:scrub(error),
    driverAvailableForExplicitRecovery:retained,automaticRetry:false,miningContainment:containment});
   if(!retained)throw Error('Failed mining action could not establish worker containment');
   // Keep the device-local backup in RAM for explicit inspection/recovery.
   // In particular an uncertain payment is never retried by this controller.
  }
  previous=command.id;if(command.action==='finish')break;
 }
 await save('BROWSER_AGGREGATE.json',{status:commandFailures?'FAIL':'PASS',commandFailures,secretsExported:false});
 if(commandFailures)process.exitCode=1;
}catch(error){await save('BROWSER_FAILURE.json',{error:scrub(error)}).catch(()=>{});process.exitCode=1;}
finally{clearTimeout(deadline);await cleanup('completed_or_failed');}
