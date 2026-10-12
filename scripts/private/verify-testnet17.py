"""Bounded loopback v17: natural PoW through TLS, real wallets, peers, transfer and browser handoff."""
import argparse,json,os,resource,signal,socket,subprocess,time,urllib.request,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--source',type=Path,required=True)
p.add_argument('--node',type=Path,required=True);p.add_argument('--run-dir',type=Path,required=True);p.add_argument('--browser',action='store_true');a=p.parse_args()
root=a.run_dir.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False);os.umask(0o077)
build=a.build.resolve(strict=True);src=a.source.resolve(strict=True);bins=build/'build/bin';children=[];receipts=[];logs=[];started=time.monotonic();password=uuid.uuid4().hex;stopped=set()
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
rpcports=[port(),port()];p2p=[port(),port()];walletports=[port() for _ in range(4)];assert len(set(rpcports+p2p+walletports))==8
def limits(node=False):
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,((128 if node else 2)*1024**3,)*2);resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,)*2)
def launch(name,argv,node=False):
 log=(root/(name+'.log')).open('xb');logs.append(log);child=subprocess.Popen(argv,cwd=root,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=lambda:limits(node));children.append((name,child,argv));return child
def rpc(port,method,params=None):
 body=json.dumps({'jsonrpc':'2.0','id':'v17','method':method,'params':params or {}}).encode()
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:'+str(port)+'/json_rpc',data=body,headers={'Content-Type':'application/json'}),timeout=30) as r:data=json.loads(r.read(4*1024**2))
 if 'error' in data:raise RuntimeError(method+': '+str(data['error']))
 return data['result']
def http(path,params):
 body=json.dumps(params).encode()
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:'+str(rpcports[0])+path,data=body,headers={'Content-Type':'application/json'}),timeout=20) as response:return json.loads(response.read(1024**2))
def pool():return sorted(http('/get_transaction_pool_hashes',{}).get('tx_hashes',[]))
def ready(port,method):
 end=time.monotonic()+60
 while time.monotonic()<end:
  assert all(c.poll() is None or c.pid in stopped for _,c,_ in children),'Owned child exited'
  try:return rpc(port,method)
  except (OSError,RuntimeError):time.sleep(.2)
 raise AssertionError('RPC deadline')
def opened(i):
 rpc(walletports[i],'refresh');return rpc(walletports[i],'get_balance')['balance']
def header(port,h):return rpc(port,'get_block_header_by_height',{'height':h,'fill_pow_hash':True})['block_header']
def wait_file(path,seconds):
 end=time.monotonic()+seconds;peak=0
 while not path.is_file() and time.monotonic()<end:
  assert all(c.poll() is None or c.pid in stopped for _,c,_ in children),'Owned child exited before checkpoint'
  if miner:
   rss=0
   for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():continue
    try:
     text=(entry/'stat').read_text();f=text[text.rfind(')')+2:].split()
     if int(f[2])==miner.pid:rss+=next((int(x.split()[1])*1024 for x in (entry/'status').read_text().splitlines() if x.startswith('VmRSS:')),0)
    except (OSError,ValueError):pass
   peak=max(peak,rss);assert rss<1024**3,'Owned miner group RSS budget exceeded'
  time.sleep(.2)
 assert path.is_file(),'Checkpoint deadline '+path.name
 return peak
def stop(*_):raise KeyboardInterrupt()
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM]:signal.signal(sig,stop)
signal.alarm(1200);miner=None
try:
 cfg=root/'empty.conf';cfg.write_text('');nodes=[]
 for i in range(2):
  data=root/('node-'+str(i));data.mkdir()
  argv=[str(bins/'meepcoind'),'--config-file',str(cfg),'--testnet','--data-dir',str(data),'--no-zmq','--disable-dns-checkpoints','--check-updates','disabled','--no-igd','--out-peers','1','--in-peers','2','--allow-local-ip','--hide-my-port','--p2p-bind-ip','127.0.0.1','--p2p-bind-port',str(p2p[i]),'--add-exclusive-node','127.0.0.1:'+str(p2p[1-i]),'--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(rpcports[i]),'--rpc-ssl','disabled','--max-concurrency','1','--prep-blocks-threads','1','--non-interactive','--log-file',str(root/('node-'+str(i)+'-internal.log')),'--log-level','0']
  nodes.append(launch('node-'+str(i),argv));info=ready(rpcports[i],'get_info');assert info['nettype']=='testnet'
 genesis=header(rpcports[0],0);pinned=json.loads((build/'CANDIDATE_NETWORK.json').read_text());assert genesis['timestamp']==pinned['genesisUtcUnix'];assert header(rpcports[1],0)['hash']==genesis['hash']
 assert rpc(rpcports[0],'hard_fork_info',{'version':17})['enabled']
 addresses=[]
 for i in range(4):
  wallets=root/('wallet-'+str(i));wallets.mkdir()
  # The wrong-network address fixture must not refresh against the testnet daemon:
  # inherited RPC protection bans repeated incompatible genesis requests by source IP.
  launch('wallet-'+str(i),[str(bins/'meepcoin-wallet-rpc'),'--config-file',str(cfg),*(['--testnet'] if i<3 else ['--offline']),'--wallet-dir',str(wallets),'--shared-ringdb-dir',str(root/('ring-'+str(i))),'--daemon-address','127.0.0.1:'+str(rpcports[0]),'--trusted-daemon','--no-dns','--daemon-ssl','disabled','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(walletports[i]),'--rpc-ssl','disabled','--disable-rpc-login','--non-interactive','--max-concurrency','1','--log-file',str(root/('wallet-'+str(i)+'-internal.log')),'--log-level','0'])
  ready(walletports[i],'get_version');rpc(walletports[i],'create_wallet',{'filename':'disposable','password':password,'language':'English'});addresses.append(rpc(walletports[i],'get_address')['address'])
  uri=rpc(walletports[i],'make_uri',{'address':addresses[i],'amount':1})['uri'];assert uri.startswith('meepcoin:');assert rpc(walletports[i],'parse_uri',{'uri':uri})['uri']['amount']==1
  try:rpc(walletports[i],'parse_uri',{'uri':uri.replace('meepcoin:','monero:',1)});raise AssertionError('Wrong URI scheme accepted')
  except RuntimeError:pass
 key=root/'key.pem';cert=root/'cert.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
 conf={'endpoint':'http://127.0.0.1:'+str(rpcports[0])+'/json_rpc','nativeHash':str(build/'pow-build/meepow-v2-hash'),'dataDirectory':str(root/'node-0'),'genesisHash':genesis['hash'],'version':info['version'],'keyFile':str(key),'certFile':str(cert),'addresses':[addresses[0],addresses[0],addresses[1],addresses[2]],'singleFirstSession':3,'network':'testnet','blockCount':77,'pauseAfter':64,'miningReady':str(root/'MINING_READY.json'),'transferReady':str(root/'TRANSFER_READY.json'),'output':str(root/'TLS.json')}
 if a.browser:conf.update(listenPort=port(),browserReady=str(root/'BROWSER_READY.json'),browserDone=str(root/'BROWSER_DONE.json'))
 cp=root/'tls-config.json';cp.write_text(json.dumps(conf));miner=launch('tls-miner',[str(a.node),'--max-old-space-size=256',str(src/'scripts/private/verify-tls-native.mjs'),str(cp)],True)
 peak=wait_file(root/'MINING_READY.json',600);before=[opened(i) for i in range(3)]
 invalid=[]
 for label,address,amount in [('wrong-network',addresses[3],1),('invalid-address','not-an-address',1),('zero',addresses[1],0),('insufficient',addresses[1],2**64-1),('negative',addresses[1],-1)]:
  prior_pool=pool()
  try:rpc(walletports[0],'transfer',{'destinations':[{'address':address,'amount':amount}],'get_tx_key':False});raise AssertionError('Invalid transfer accepted: '+label)
  except RuntimeError as error:invalid.append({'label':label,'error':str(error),'unchangedBalance':opened(0)==before[0],'unchangedPool':pool()==prior_pool})
 assert all(x['unchangedBalance'] and x['unchangedPool'] for x in invalid)
 for blob in ['00','ff'*64]:
  try:rpc(rpcports[0],'submit_block',[blob]);raise AssertionError('Malformed block accepted')
  except RuntimeError:pass
  assert rpc(rpcports[0],'get_info')['height']==65
 malformed_tx=http('/send_raw_transaction',{'tx_as_hex':'00','do_not_relay':False});assert malformed_tx['status']!='OK';assert pool()==[]
 # Wallet C has exactly one mined output, so two unrelayed spends must conflict.
 spend1=rpc(walletports[2],'transfer',{'destinations':[{'address':addresses[0],'amount':100000000000}],'ring_size':16,'get_tx_key':False,'get_tx_hex':True,'do_not_relay':True})
 spend2=rpc(walletports[2],'transfer',{'destinations':[{'address':addresses[1],'amount':200000000000}],'ring_size':16,'get_tx_key':False,'get_tx_hex':True,'do_not_relay':True})
 assert spend1['tx_hash']!=spend2['tx_hash']
 first=http('/send_raw_transaction',{'tx_as_hex':spend1['tx_blob'],'do_not_relay':False});assert first['status']=='OK'
 prior_pool=pool();assert prior_pool==[spend1['tx_hash']]
 second=http('/send_raw_transaction',{'tx_as_hex':spend2['tx_blob'],'do_not_relay':False});assert second['status']!='OK' and second.get('double_spend');assert pool()==prior_pool
 tx=rpc(walletports[0],'transfer',{'destinations':[{'address':addresses[1],'amount':100000000000}],'ring_size':16,'get_tx_key':False,'get_tx_hex':False});assert tx['amount']==100000000000
 (root/'TRANSFER_READY.json').write_text(json.dumps({'txHash':tx['tx_hash']})+'\n')
 if a.browser:peak=max(peak,wait_file(root/'BROWSER_READY.json',400));print('BROWSER_READY '+str(root/'BROWSER_READY.json'),flush=True)
 end=time.monotonic()+(240 if a.browser else 400)
 while miner.poll() is None and time.monotonic()<end:time.sleep(.2)
 assert miner.poll()==0,'TLS miner failed or timed out';stopped.add(miner.pid)
 height=rpc(rpcports[0],'get_info')['height'];assert height==(80 if a.browser else 78)
 end=time.monotonic()+90
 while time.monotonic()<end:
  heads=[rpc(x,'get_last_block_header')['block_header'] for x in rpcports]
  if heads[0]['hash']==heads[1]['hash']:break
  time.sleep(.5)
 assert heads[0]['hash']==heads[1]['hash'],'Peer convergence'
 allheaders=[[header(port,h) for h in range(1,height)] for port in rpcports]
 for hs in allheaders:
  cumulative=1
  for h in hs:
   assert h['major_version']==17 and h['difficulty']>=20 and not h['orphan_status']
   assert int.from_bytes(bytes.fromhex(h['pow_hash']),'little')*int(h['wide_difficulty'],16)<2**256
   cumulative+=int(h['wide_difficulty'],16);assert cumulative==int(h['wide_cumulative_difficulty'],16)
 after=[opened(i) for i in range(3)];rows=json.loads((root/'TLS.json').read_text())['rows'];rewards=[0,0]
 for row in rows[64:]:rewards[1 if row['session']==2 else 0]+=allheaders[0][int(row['height'])-1]['reward']
 if a.browser:
  rewards[0]+=sum(h['reward'] for h in allheaders[0][-2:])
 assert after[0]-before[0]==rewards[0]-tx['amount']-tx['fee']+spend1['amount'];assert after[1]-before[1]==rewards[1]+tx['amount'];assert after[2]-before[2]==-spend1['amount']-spend1['fee']
 incoming=rpc(walletports[1],'get_transfer_by_txid',{'txid':tx['tx_hash']})['transfer'];assert incoming['confirmations']>=10
 for i in range(3):
  rpc(walletports[i],'store');rpc(walletports[i],'close_wallet');rpc(walletports[i],'open_wallet',{'filename':'disposable','password':password});rpc(walletports[i],'rescan_blockchain');assert opened(i)==after[i]
 # A bound listener is not proof that core RPC is ready: inherited header RPC
 # returns status BUSY with a default header during startup. Keep the observed
 # statuses and require the persisted tip after readiness, within a deadline.
 restart_observations=[]
 for i,node in enumerate(nodes):
  os.killpg(node.pid,signal.SIGTERM);assert node.wait(timeout=20)==0;stopped.add(node.pid);restarted=launch('node-restart-'+str(i),children[i][2]);ready(rpcports[i],'get_info')
  deadline=time.monotonic()+60;observed=[]
  while time.monotonic()<deadline:
   response=rpc(rpcports[i],'get_last_block_header');h=response.get('block_header',{});observed.append({'status':response.get('status'),'height':h.get('height'),'hash':h.get('hash')})
   if response.get('status')=='OK' and h.get('hash')==heads[0]['hash']:break
   assert restarted.poll() is None,'Restarted daemon exited';time.sleep(.2)
  restart_observations.append({'node':i,'observations':observed})
  (root/'RESTART_OBSERVATIONS.json').write_text(json.dumps(restart_observations,indent=2)+'\n')
  assert observed[-1]['status']=='OK' and observed[-1]['hash']==heads[0]['hash'],'Persisted canonical tip not ready by deadline'
 result={'status':'REAL_TESTNET17_NATURAL_TLS_CURRENCY_PEERS_PASS','version':info['version'],'genesis':genesis,'pinnedGenesisUtcUnix':pinned['genesisUtcUnix'],'actualPowBlocks':height-1,'canonicalReadbacks':2*(height-1),'hardfork17ActivatedAtHeight1':True,'naturalDifficulty':True,'difficultyMin':min(h['difficulty'] for h in allheaders[0]),'difficultyMax':max(h['difficulty'] for h in allheaders[0]),'headers':allheaders,'senderBefore':before[0],'senderAfter':after[0],'recipientBefore':before[1],'recipientAfter':after[1],'confirmationRewardsByWallet':rewards,'amountAtomic':tx['amount'],'feeAtomic':tx['fee'],'txHash':tx['tx_hash'],'confirmations':incoming['confirmations'],'exactAccounting':True,'invalidTransfers':invalid,'malformedRpcRejected':True,'doubleSpend':{'firstHash':spend1['tx_hash'],'conflictingHash':spend2['tx_hash'],'amountAtomic':spend1['amount'],'feeAtomic':spend1['fee'],'rejection':second,'singlePoolEntry':True,'thirdWalletBefore':before[2],'thirdWalletAfter':after[2]},'walletReopenRescan':True,'peerRestart':True,'meepcoinUriRoundTrip':True,'moneroUriRejected':True,'browserBlocks':2 if a.browser else 0,'peakObservedOwnedMinerRssBytes':peak,'publicExposure':False}
 (root/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['status','actualPowBlocks','difficultyMax','browserBlocks','txHash']}),flush=True)
finally:
 signal.alarm(0)
 for name,c,_ in reversed(children):
  if c.poll() is None:
   os.killpg(c.pid,signal.SIGTERM)
   try:c.wait(timeout=20)
   except subprocess.TimeoutExpired:os.killpg(c.pid,signal.SIGKILL);c.wait(timeout=10)
  try:os.killpg(c.pid,0);empty=False
  except ProcessLookupError:empty=True
  receipts.append({'name':name,'pid':c.pid,'exitCode':c.returncode,'ownedGroupEmpty':empty})
 for log in logs:log.close()
 (root/'CLEANUP.json').open('x').write(json.dumps({'processes':receipts,'elapsedSeconds':time.monotonic()-started},indent=2)+'\n')
 assert all(x['ownedGroupEmpty'] for x in receipts)
