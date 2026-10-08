// Reserve an OS-selected local port, then release it for a refusal/no-listener assertion.
// Fixed ports became unreliable on Windows even when no listener appears in netstat.
import { createServer } from 'node:http';

export async function availablePort() {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolve);
  });
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}
