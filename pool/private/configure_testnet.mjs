// Generate owner-readable operator configuration and invitation links. No spend keys.
import {parseArgs} from 'node:util';
import {randomBytes} from 'node:crypto';
import {writeFile,readFile,lstat} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {experimentWindow} from './experiment.mjs';
import {validateTlsIdentity} from './tls_identity.mjs';
const {values}=parseArgs({options:Object.fromEntries(
 ['out','origin','endpoint','genesis','genesis-utc','version','key','cert','data','address','host','port','native','contact','duration-seconds'].map(k=>[k,{type:'string',multiple:k==='address'}]))});
for(const k of ['out','origin','endpoint','genesis','genesis-utc','version','key','cert','data','address','native','contact'])if(!values[k])throw Error('--'+k+' required');
const origin=new URL(values.origin);
if(origin.protocol!=='https:'||origin.origin!==values.origin)throw Error('exact HTTPS origin required');
const endpoint=new URL(values.endpoint);
if(endpoint.protocol!=='http:'||endpoint.hostname!=='127.0.0.1'||endpoint.pathname!=='/json_rpc'||endpoint.username||endpoint.password||endpoint.search||endpoint.hash)
 throw Error('daemon endpoint must be numeric IPv4 loopback /json_rpc');
if(!/^[a-f0-9]{64}$/.test(values.genesis))throw Error('64-hex genesis required');
if(values.address.length<1||values.address.length>8||values.address.some(a=>!/^[1-9A-HJ-NP-Za-km-z]{90,110}$/.test(a)))throw Error('1..8 public reward addresses required');
if(new Set(values.address).size!==values.address.length)throw Error('unique participant addresses required');
if(!values.contact.trim()||values.contact.length>200||/[\r\n\x00-\x1f]/.test(values.contact))throw Error('plain incident contact required');
if(!/^[0-9]{10}$/.test(values['genesis-utc']))throw Error('ten-digit --genesis-utc required');
if(!/^\d{1,4}$/.test(values['duration-seconds']??'3600'))throw Error('duration 1..3600 seconds required');
const utc=Math.floor(Date.now()/1000),duration=Number(values['duration-seconds']??3600);
if(duration<1||duration>3600)throw Error('duration 1..3600 seconds required');
const experiment={genesisUtcUnix:Number(values['genesis-utc']),startsUtcUnix:utc,endsUtcUnix:utc+duration};
experimentWindow(experiment);
await validateTlsIdentity({origin:values.origin,key:await readFile(values.key),cert:await readFile(values.cert),endsUtcUnix:experiment.endsUtcUnix});
const port=Number(values.port??(origin.port||443));if(!Number.isInteger(port)||port<1||port>65535)throw Error('port 1..65535 required');
const path=resolve(values.out),inviteOutput=path+'.invitations.json',availabilityFile=path+'.progress.json';
const directory=await lstat(dirname(path));
if(!directory.isDirectory()||directory.isSymbolicLink()||(process.platform!=='win32'&&((directory.mode&0o077)!==0||directory.uid!==process.getuid())))throw Error('owner-only operator directory required');
for(const destination of [path,inviteOutput,availabilityFile]){
 try{await lstat(destination);throw Error('operator output already exists');}catch(error){if(error.code!=='ENOENT')throw error;}
}
const sessions=values.address.map(walletAddress=>({walletAddress,token:randomBytes(32).toString('hex')}));
const config={origin:values.origin,endpoint:values.endpoint,expectedNetwork:'testnet',expectedGenesisHash:values.genesis,expectedVersion:values.version,
 host:values.host??'127.0.0.1',port,keyFile:resolve(values.key),certFile:resolve(values.cert),dataDirectory:resolve(values.data),inviteOutput,
 nativeCommand:[resolve(values.native)],sessionTtlMs:duration*1000,maxJobs:32,sessions,experiment,incidentContact:values.contact,availabilityFile};
await writeFile(availabilityFile,JSON.stringify({schema:'meepcoin-progress/1',genesis:values.genesis,height:0,tip:null,lastProgressMs:utc*1000,closed:false})+'\n',{flag:'wx',mode:0o600});
await writeFile(path,JSON.stringify(config,null,2)+'\n',{flag:'wx',mode:0o600});
await writeFile(inviteOutput,JSON.stringify({origin:values.origin,sessions:sessions.map(s=>({walletAddress:s.walletAddress,url:values.origin+'/#session='+s.token}))},null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({config:path,invitations:inviteOutput,publicExposure:false}));
