import {X509Certificate,createPublicKey} from 'node:crypto';
import {isIP} from 'node:net';

// Check the same hostname/key/validity at generation and every CLI startup.
// This validates identity; CA trust still belongs to the deployed browser path.
export function validateTlsIdentity({origin,key,cert,endsUtcUnix},now=Date.now()) {
  const certificate=new X509Certificate(cert);
  const hostname=new URL(origin).hostname.replace(/^\[|\]$/g,'');
  const from=Date.parse(certificate.validFrom),to=Date.parse(certificate.validTo);
  if(!Number.isFinite(from)||!Number.isFinite(to)||!Number.isFinite(now)
    ||!Number.isSafeInteger(endsUtcUnix)||from>now||to<=endsUtcUnix*1000)
    throw Error('certificate validity does not cover experiment');
  // checkIP is selected by Node's standard IP parser, not a hostname heuristic.
  if(!(isIP(hostname)?certificate.checkIP(hostname):certificate.checkHost(hostname,
      {subject:'never',partialWildcards:false,multiLabelWildcards:false,singleLabelSubdomains:false})))
    throw Error('certificate does not match origin hostname');
  if(!certificate.publicKey.export({type:'spki',format:'der'}).equals(
    createPublicKey(key).export({type:'spki',format:'der'})))throw Error('certificate and private key do not match');
}
