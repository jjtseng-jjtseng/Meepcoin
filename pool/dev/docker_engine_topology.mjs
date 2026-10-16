// The private daemon path uses Ubuntu WSL localhost and WSL `ss` to observe the container. Docker
// Desktop's host-networked containers instead live in its own VM. Detect that known mismatch before
// starting a daemon, and (in the one-use browser runner) before spending a reservation. Other
// engine labels are not proof of shared networking; the later RPC/listener observations remain.
export function classifyWslDockerEngine({ status, stdout }) {
  if (status !== 0) return { ok: false, error: 'the WSL Docker engine could not be identified' };
  let labels;
  try { labels = JSON.parse(String(stdout).trim()); } catch { /* fail closed below */ }
  if (!Array.isArray(labels) || !labels.every((label) => typeof label === 'string')) {
    return { ok: false, error: 'the WSL Docker engine labels were malformed' };
  }
  if (labels.some((label) => label.startsWith('com.docker.desktop.address='))) {
    return { ok: false, error: 'Docker Desktop uses a different host network than Ubuntu WSL; this WSL-loopback runner requires a WSL-local Docker engine' };
  }
  return { ok: true, error: null };
}
