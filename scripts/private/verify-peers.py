"""Owned, bounded private regtest; fresh disposable wallets, no existing user keys."""
from pathlib import Path
import argparse,hashlib,json,os,resource,signal,socket,struct,subprocess,time,urllib.request,uuid
parser=argparse.ArgumentParser(description='Bounded real peer partition/fork/restart test; fresh disposable wallets only')
parser.add_argument('--binaries',type=Path,required=True);parser.add_argument('--run-dir',type=Path,required=True)
parser.add_argument('--library-dir',type=Path)
parser.add_argument('--extended',action='store_true',help='20 vs 24 block fork and malformed wire probes')
args=parser.parse_args()
runroot=args.run_dir.resolve();runroot.mkdir(mode=0o700,parents=True,exist_ok=False)
bins=args.binaries.resolve(strict=True)
for name in ['meepcoind','meepcoin-wallet-rpc']:assert (bins/name).is_file()
env=dict(os.environ,LC_ALL='C')
if args.library_dir:env['LD_LIBRARY_PATH']=str(args.library_dir.resolve(strict=True))
children=[];logs=[];receipts=[];expected_stopped=set();started=time.monotonic();deadline=started+600
def free_port():
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
daemon_port,wallet_a_port,wallet_b_port=free_port(),free_port(),free_port()
assert len({daemon_port,wallet_a_port,wallet_b_port})==3
password=uuid.uuid4().hex
os.umask(0o077)
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2))
def stop(sig,frame):raise KeyboardInterrupt()
for sig in [signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM]:signal.signal(sig,stop)
signal.alarm(600)
def rpc(port,method,params=None,timeout=120):
 body=json.dumps({'jsonrpc':'2.0','id':'private','method':method,'params':params or {}}).encode()
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+'/json_rpc',data=body,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=timeout) as r:
  raw=r.read(4*1024**2+1);assert len(raw)<=4*1024**2;result=json.loads(raw)
 if 'error' in result:raise RuntimeError(method+': '+str(result['error']))
 return result['result']
def launch(name,argv):
 log=(runroot/(name+'.log')).open('xb');logs.append(log)
 p=subprocess.Popen(argv,cwd=runroot,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True,preexec_fn=limits)
 children.append((name,p,argv));return p
def wait_rpc(port,method,params=None):
 until=min(deadline,time.monotonic()+60)
 while time.monotonic()<until:
  for name,p,argv in children:
   if p.poll() is not None and p.pid not in expected_stopped:raise RuntimeError(name+' exited early '+str(p.returncode))
  try:return rpc(port,method,params,timeout=3)
  except (OSError,RuntimeError):time.sleep(.5)
 raise RuntimeError('RPC not ready')
def mine(amount,address):
 assert 1<=amount<=80
 return rpc(daemon_port,'generateblocks',{'amount_of_blocks':amount,'wallet_address':address},timeout=600)

def peer_limit(port,direction,count):
 body=json.dumps({'set':True,direction+'_peers':count}).encode()
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+'/'+direction+'_peers',data=body,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=10) as r:result=json.loads(r.read(4096))
 assert result[direction+'_peers']==count
 return result

def head(i):return rpc(rpcports[i],'get_last_block_header')['block_header']
def converge(expected_hash=None):
 until=min(deadline,time.monotonic()+120)
 while time.monotonic()<until:
  hs=[head(i) for i in range(3)]
  if len({x['hash'] for x in hs})==1 and (expected_hash is None or hs[0]['hash']==expected_hash):return hs
  time.sleep(.5)
 raise RuntimeError('Private peers did not converge before deadline')
def mining(i,amount,address,nonce=0):
 assert 1<=amount<=20
 return rpc(rpcports[i],'generateblocks',{'amount_of_blocks':amount,'wallet_address':address,'starting_nonce':nonce},timeout=120)
def shutdown_owned(p):
 os.killpg(p.pid,signal.SIGTERM);assert p.wait(timeout=20)==0
 expected_stopped.add(p.pid)
 try:os.killpg(p.pid,0);raise RuntimeError('Stopped owned group remains')
 except ProcessLookupError:pass
try:
 cfg=runroot/'empty.conf';cfg.write_text('')
 rpcports=[daemon_port,free_port(),free_port()];p2pports=[free_port() for _ in range(3)]
 assert len(set(rpcports+p2pports+[wallet_a_port,wallet_b_port]))==8
 nodes=[]
 for i in range(3):
  data=runroot/('node-'+str(i));data.mkdir()
  argv=[str(bins/'meepcoind'),'--config-file',str(cfg),'--data-dir',str(data),'--regtest','--keep-fakechain','--fixed-difficulty','20',
   '--no-zmq','--disable-dns-checkpoints','--check-updates','disabled','--no-igd','--out-peers','1','--in-peers','2',
   '--allow-local-ip','--hide-my-port','--p2p-bind-ip','127.0.0.1','--p2p-bind-port',str(p2pports[i]),
   '--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(rpcports[i]),'--rpc-ssl','disabled',
   '--max-concurrency','1','--prep-blocks-threads','1','--non-interactive',
   '--add-exclusive-node','127.0.0.1:'+str(p2pports[(i+2)%3]),
   '--log-file',str(runroot/('node-'+str(i)+'-internal.log')),'--log-level','0',
   '--max-log-files','1','--max-log-file-size','8388608']
  p=launch('node-'+str(i),argv);wait_rpc(rpcports[i],'get_info');nodes.append((p,argv))
 for name,port in [('wallet-a',wallet_a_port),('wallet-b',wallet_b_port)]:
  d=runroot/name;d.mkdir();ring=runroot/(name+'-ringdb');ring.mkdir()
  launch(name,[str(bins/'meepcoin-wallet-rpc'),'--config-file',str(cfg),'--wallet-dir',str(d),
   '--shared-ringdb-dir',str(ring),'--daemon-address','127.0.0.1:'+str(daemon_port),'--trusted-daemon',
   '--no-dns','--daemon-ssl','disabled','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(port),
   '--rpc-ssl','disabled','--disable-rpc-login','--non-interactive','--max-concurrency','1',
   '--log-file',str(runroot/(name+'-internal.log')),'--log-level','0'])
  wait_rpc(port,'get_version');rpc(port,'create_wallet',{'filename':'disposable','password':password,'language':'English'},timeout=90)
 a=rpc(wallet_a_port,'get_address')['address'];b=rpc(wallet_b_port,'get_address')['address']
 baseblocks=mining(0,4,a)['blocks'];baseheads=converge(baseblocks[-1])
 initial_connections=[rpc(port,'get_connections').get('connections',[]) for port in rpcports]
 assert all(initial_connections),'Initial connected network required'
 (runroot/'INITIAL_CONNECTIONS.json').open('x').write(json.dumps(initial_connections,indent=2)+'\n')
 wire=[]
 if args.extended:
  original=head(0)['hash']
  def frame(signature,length,command=1001,flags=1,version=1,payload=b''):
   return struct.pack('<QQBIiII',signature,length,1,command,0,flags,version)+payload
  cases=[('bad-signature',frame(0,0)),('declared-oversize',frame(0x0101010101012101,2**64-1)),
   ('malformed-handshake',frame(0x0101010101012101,32,payload=b'\xff'*32)),
   ('unknown-command',frame(0x0101010101012101,1,command=0xffffffff,payload=b'\0')),
   ('truncated-header',b'\x01\x21\x01'),('unknown-version',frame(0x0101010101012101,0,version=0xffffffff))]
  for index,(label,payload) in enumerate(cases):
   assert len(payload)<=65536
   with socket.socket() as connection:
    connection.settimeout(2);connection.bind(('127.0.0.'+str(index+2),0));connection.connect(('127.0.0.1',p2pports[0]))
    connection.sendall(payload);connection.shutdown(socket.SHUT_WR)
    try:reply=connection.recv(4096);outcome='closed' if not reply else 'response'
    except (TimeoutError,ConnectionResetError):outcome='timeout-or-reset'
   assert head(0)['hash']==original,'Malformed peer changed canonical tip'
   assert nodes[0][0].poll() is None,'Malformed peer crashed daemon'
   wire.append({'label':label,'sentHex':payload.hex(),'outcome':outcome,'daemonAlive':True,'canonicalTipUnchanged':True})
  (runroot/'WIRE.json').open('x').write(json.dumps(wire,indent=2)+'\n')
 peer_limit(rpcports[0],'out',0);peer_limit(rpcports[0],'in',0)
 until=min(deadline,time.monotonic()+20)
 while rpc(rpcports[0],'get_connections').get('connections',[]) and time.monotonic()<until:time.sleep(.2)
 assert not rpc(rpcports[0],'get_connections').get('connections',[]),'Partition failed to disconnect node zero'
 shortblocks=mining(0,20 if args.extended else 2,a)['blocks'];shorthead=head(0)
 longblocks=[]
 for count in ([20,4] if args.extended else [4]):longblocks.extend(mining(1,count,b,100000+len(longblocks)*1000)['blocks'])
 longhead=head(1)
 until=min(deadline,time.monotonic()+60)
 while head(2)['hash']!=longhead['hash'] and time.monotonic()<until:time.sleep(.5)
 assert head(2)['hash']==longhead['hash'] and head(0)['hash']==shorthead['hash']
 assert shortblocks[0]!=longblocks[0] and shorthead['height']<longhead['height']
 rpc(wallet_a_port,'refresh');before=rpc(wallet_a_port,'get_balance')['balance']
 expected_before=sum(rpc(rpcports[0],'get_block_header_by_hash',{'hash':h})['block_header']['reward'] for h in baseblocks+shortblocks)
 assert before==expected_before
 partition={'base':baseheads,'shortBranch':shorthead,'longBranch':longhead,'shortBlocks':shortblocks,'longBlocks':longblocks,
  'isolatedConnections':rpc(rpcports[0],'get_connections').get('connections',[]),'survivingPairConnections':[rpc(port,'get_connections').get('connections',[]) for port in rpcports[1:]],'senderBalanceBeforeReorg':before}
 assert all(partition['survivingPairConnections'])
 (runroot/'PARTITION.json').open('x').write(json.dumps(partition,indent=2)+'\n')
 peer_limit(rpcports[0],'out',1);peer_limit(rpcports[0],'in',2)
 rejoined=converge(longhead['hash'])
 assert all(h['wide_cumulative_difficulty']==longhead['wide_cumulative_difficulty'] for h in rejoined)
 rpc(wallet_a_port,'refresh');rpc(wallet_b_port,'refresh')
 after=rpc(wallet_a_port,'get_balance')['balance'];bafter=rpc(wallet_b_port,'get_balance')['balance']
 base_reward=sum(rpc(daemon_port,'get_block_header_by_hash',{'hash':h})['block_header']['reward'] for h in baseblocks)
 winning_reward=sum(rpc(daemon_port,'get_block_header_by_hash',{'hash':h})['block_header']['reward'] for h in longblocks)
 assert after==base_reward and after<before and bafter==winning_reward,'Wallet reorg accounting incorrect'
 extension=mining(0,2,b,200000)['blocks'];finalheads=converge(extension[-1])
 p,argv=nodes[2];shutdown_owned(p);launch('node-2-restarted',argv);wait_rpc(rpcports[2],'get_info');restartheads=converge(extension[-1])
 rpc(wallet_a_port,'rescan_blockchain');rpc(wallet_a_port,'refresh');assert rpc(wallet_a_port,'get_balance')['balance']==base_reward
 rpc(wallet_b_port,'rescan_blockchain');rpc(wallet_b_port,'refresh')
 canonical_hashes=baseblocks+longblocks+extension
 canonical=[]
 for i,port in enumerate(rpcports):
  hs=[rpc(port,'get_block_header_by_height',{'height':height,'fill_pow_hash':True})['block_header'] for height in range(1,len(canonical_hashes)+1)]
  assert [h['hash'] for h in hs]==canonical_hashes
  assert all(not h['orphan_status'] and h['difficulty']==20 and int.from_bytes(bytes.fromhex(h['pow_hash']),'little')*20<2**256 for h in hs)
  canonical.append({'node':i,'headers':hs})
 expected_b=sum(h['reward'] for h in canonical[0]['headers'][len(baseblocks):])
 assert rpc(wallet_b_port,'get_balance')['balance']==expected_b
 raw={'partition':partition,'rejoined':rejoined,'finalHeads':finalheads,'restartHeads':restartheads,'canonical':canonical,'walletAAfterReorg':after,'walletBAfterReorg':bafter,'walletBAfterExtension':expected_b,'initialConnections':initial_connections}
 (runroot/'RAW.json').open('x').write(json.dumps(raw,indent=2)+'\n')
 result={'status':'PRIVATE_PEER_PARTITION_REORG_PASS','nodes':3,'fixedDifficulty':20,'baseBlocks':len(baseblocks),'losingBlocks':len(shortblocks),'winningBlocks':len(longblocks),'postRejoinBlocks':len(extension),'canonicalReadbacks':sum(len(x['headers']) for x in canonical),'partitionProvenDisconnected':True,'survivingPairSynchronized':True,'higherWorkConvergence':True,'walletOrphanRewardsRemoved':True,'exactWinningRewardAccounting':True,'walletRescans':True,'nodeRestart':True,'malformedWireCases':wire,'topHeight':finalheads[0]['height'],'topHash':finalheads[0]['hash'],'limits':['Private loopback regtest with fixed difficulty 20','Finite malformed frames and honest competing branches; no comprehensive malicious-peer or adversarial retarget policy claim','Fresh disposable wallets only; no seed or password exported']}
 (runroot/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
finally:
 signal.alarm(0)
 for name,p,argv in reversed(children):
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=20)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
  try:os.killpg(p.pid,0);empty=False
  except ProcessLookupError:empty=True
  receipts.append({'name':name,'pid':p.pid,'exitCode':p.returncode,'ownedGroupEmpty':empty})
 for log in logs:log.close()
 (runroot/'CLEANUP.json').open('x').write(json.dumps({'processes':receipts,'elapsedSeconds':time.monotonic()-started},indent=2)+'\n')
 assert all(x['ownedGroupEmpty'] for x in receipts),'owned process cleanup incomplete'
