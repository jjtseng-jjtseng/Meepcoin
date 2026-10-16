"""Failure-path ownership regressions; actual-native tests live in verify_crash.py."""
import json,os,signal,socket,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import guarded
import session

@unittest.skipUnless(os.name=='posix','POSIX guardian and private Unix socket')
class OwnershipTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.root.chmod(0o700)
 def until(self,fn):
  end=time.monotonic()+10
  while time.monotonic()<end:
   if fn():return
   time.sleep(.02)
  self.fail('Owned checkpoint timeout')
 def test_fast_exit_and_missing_or_malformed_receipt_never_signal_reaped_pid(self):
  sentinel=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
  self.addCleanup(lambda:(sentinel.terminate(),sentinel.wait(timeout=5)))
  for mode in ('intact','missing','malformed'):
   receipt=self.root/(mode+'-GUARD_STOPPED.json')
   with (self.root/(mode+'.log')).open('xb') as output:
    child=guarded.Child([sys.executable,'-c','pass'],output=output,receipt=receipt,seconds=5)
    self.until(receipt.exists)
    if mode=='missing':receipt.unlink()
    if mode=='malformed':receipt.write_text('{')
    self.assertEqual(child.wait(timeout=10),0 if mode=='intact' else 1)
    child.guardian_pid=sentinel.pid # Simulate a saved PID now identifying another process.
    with patch.object(guarded.os,'kill') as kill:
     child.terminate();self.assertFalse(kill.called)
    self.assertIsNone(sentinel.poll())
 def test_observer_failure_still_kills_term_resistant_owned_child(self):
  receipt=self.root/'observer-GUARD_STOPPED.json';ready=self.root/'ready'
  code='import signal,time,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);pathlib.Path('+repr(str(ready))+').write_text("ready");time.sleep(60)'
  with (self.root/'observer.log').open('xb') as output:
   with patch.object(guarded,'_group_live',side_effect=OSError('Injected observation failure')):
    child=guarded.Child([sys.executable,'-c',code],output=output,receipt=receipt,seconds=5)
   self.until(ready.exists);child.kill();self.assertEqual(child.wait(timeout=45),1)
  record=json.loads(receipt.read_text());self.assertFalse(record['ownedGroupDrained']);self.assertEqual(record['error'],'OSError')
  self.assertLess(record['drainAfterOwnershipLossSeconds'],10)
  with self.assertRaises(ProcessLookupError):os.kill(child.pid,0)
 def fixture(self):
  owner={'schema':'meepcoin-session-owner/1','session':'session-'+'a'*16,'genesis':'b'*64,'releaseVersion':'test'}
  run=self.root/owner['session'];run.mkdir(mode=0o700)
  def save(path,obj):
   path.write_text(json.dumps(obj));path.chmod(0o600)
  save(run/'OWNER.json',owner)
  control=self.root/'control.sock';sock=socket.socket(socket.AF_UNIX);sock.bind(str(control));sock.close();control.chmod(0o600)
  save(self.root/'ACTIVE_SESSION.json',{'schema':'meepcoin-session-ownership/1',**{k:owner[k] for k in ('session','genesis','releaseVersion')},
    'controlInode':control.stat().st_ino,'startedUtc':time.time(),'children':['peer-GUARD_STOPPED.json']})
  record={'schema':'meepcoin-owned-child/1','owner':owner,'ownedGroupDrained':True,'error':None,'nativePid':os.getpid()}
  save(run/'peer-GUARD_STOPPED.json',record)
  return owner,run,control,record,save
 def test_forged_owner_and_nonboolean_drain_refused_without_signals(self):
  owner,run,control,record,save=self.fixture()
  for change in ({'owner':{**owner,'genesis':'c'*64}},{'ownedGroupDrained':'true'}):
   save(run/'peer-GUARD_STOPPED.json',{**record,**change})
   with patch.object(session.os,'kill') as kill,self.assertRaises(ValueError):session.recover(self.root,control)
   self.assertFalse(kill.called);self.assertTrue(control.exists())
 def test_exact_nested_run_proof_required_regardless_of_directory_mtime(self):
  owner,run,control,record,save=self.fixture()
  parent=self.root/'node';parent.mkdir(mode=0o700);native=parent/('node-session-'+'d'*16);native.mkdir(mode=0o700)
  os.utime(native,(1,1))
  save(run/'native-node.json',{'owner':owner,'run':str(native)})
  with self.assertRaises(FileNotFoundError):session.recover(self.root,control)
  self.assertTrue(control.exists());save(native/'GUARD_STOPPED.json',record)
  session.recover(self.root,control);self.assertFalse(control.exists());self.assertTrue((run/'RECOVERED.json').exists())
 def test_recovery_interrupted_after_receipt_can_finish_without_signals(self):
  owner,run,control,record,save=self.fixture()
  original=Path.unlink
  def interrupt(path,*args,**kwargs):
   if path==control:raise InterruptedError('Injected interruption before socket removal')
   return original(path,*args,**kwargs)
  with patch.object(Path,'unlink',interrupt),self.assertRaises(InterruptedError):session.recover(self.root,control)
  self.assertTrue(control.exists());self.assertTrue((run/'RECOVERED.json').exists())
  with patch.object(session.os,'kill') as kill:session.recover(self.root,control)
  self.assertFalse(kill.called);self.assertFalse(control.exists())

if __name__=='__main__':unittest.main()
