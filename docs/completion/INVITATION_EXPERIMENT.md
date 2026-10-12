# MeepCoin desktop invitation experiment

This is a bounded browser solo-mining experiment with test coins. Rewards go to
each invitation's public testnet address. Coins have no promised monetary value.
There is no sale, pool balance, profitability promise or mainnet launch.

## Participation

The first epoch admits at most eight invitations for one hour, with no automatic
renewal. A participant explicitly presses Start. One worker searches for at most
two minutes or 8,192 nonces. Stop, hiding the tab, navigation and reload end mining.
Returning to the tab never resumes it. Keep the browser window visible and stop if
the computer becomes uncomfortable or other work slows down. Background mining
and mobile phones are outside this experiment.

Desktop Windows Chrome is the initial supported participant platform. Linux
Firefox and Mac Chrome have frozen-hash qualification, with their recorded memory
limits. Safari has real hash and lifecycle checks but is not advertised for native
reward mining until its visible-window native-block qualification passes. Full
Windows/macOS native node and wallet distributions are separate work. The native
review package is Debian 13 ARM64.

The network needs approximately 0.5 aggregate hashes/second for its studied startup
assumption. This is an expectation, not an uptime or block-time guarantee. Blocks
can stall for hours after large miners depart, and stop entirely if nobody mines.
The Pi runs the node; it does not secretly mine to maintain apparent activity.
Coinbase maturity requires ten further blocks. A quiet experiment may end before
a reward matures. Fees use integer amounts with eleven decimal places, and chain
reorganizations can remove rewards. The emission includes a permanent 0.125 MEEP
tail per block; 25 million MEEP is not a hard supply cap.

## Stop, incidents and reset

Report non-secret incidents at
https://github.com/jjtseng-jjtseng/Meepcoin/issues/new/choose . Include the browser
version, approximate UTC time, public release identifier, a short description and
whether Stop worked. Never include invitation URLs/tokens, a seed, passwords,
wallet files, personal information or chain databases. A public reward address is
optional. A chatbot may explain documentation but cannot authorize recovery or
promise a response. There is no guaranteed support response time.

The operator closes admission immediately on mismatched hashes/network identity,
unknown submission outcome requiring reconciliation, resource guard failure,
unexpected service exit, unexplained reward discrepancy, leaked invitation or a
review finding affecting the intended exposure. The saved end time closes the
epoch even after a service restart. A failed service stays stopped; it is not
restarted automatically.

The operator preserves release hashes, genesis, canonical tip and bounded logs,
then reconciles any already-dispatched candidate with the native chain before
retrying. A reset requires a public notice, a new pinned network/genesis manifest
and fresh database paths. Old balances are not represented as carrying over. No
automatic renewal, silent reset, public native P2P, or automatic computer handover
is authorized by this experiment's release packet.

## Deployment decision

The website is https://meepcoin.me . The intended mining origin is
https://mine.meepcoin.me . Publishing that origin requires account-controlled DNS,
public certificate/routing verification and a rehearsal through that exact path.
Localhost TLS and SSH tunnels are labelled local rehearsal, never public endpoint
qualification. Invitations remain private until those checks and the recorded
exposure review pass. The user's instruction to complete deployment authorizes
the engineering work; missing checks still prevent a pass claim.
