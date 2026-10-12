#!/usr/bin/env python3
"""Build the frozen portable v2 API with the existing compiler; no package installation."""
import argparse, hashlib, json, os, platform, resource, signal, subprocess, time
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cc', default='clang')
    parser.add_argument('--cxx', default='clang++')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / 'meepow'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, LC_ALL='C')
    receipts = []
    def limits():
        os.nice(10)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
        resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2, 128 * 1024**2))
    def run(label, argv):
        started = time.monotonic()
        with (output / (label + '.log')).open('xb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                env=env, start_new_session=True, preexec_fn=limits)
            try:
                code = child.wait(timeout=240)
            except BaseException:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                raise
        try:
            os.killpg(child.pid, 0)
            empty = False
        except ProcessLookupError:
            empty = True
        receipts.append(dict(label=label, argv=argv, exitCode=code,
            ownedGroupEmpty=empty, elapsedSeconds=time.monotonic() - started))
        if code or not empty:
            raise RuntimeError(label + ' failed; inspect preserved log')
    inputs = [source / 'third_party/blake3' / (name + '.c')
              for name in ['blake3', 'blake3_dispatch', 'blake3_portable']]
    inputs += [source / path for path in ['src/v2_api.cpp', 'src/v2_capi.cpp', 'tests/kat_v2_api.cpp', 'tests/target_math.cpp']]
    identity_paths = sorted(set(inputs + list((source/'src').glob('*.hpp')) +
        list((source/'include/meepow').glob('*')) + list((source/'third_party/blake3').glob('*.h')) +
        [source/'vectors/vectors_v2.txt']))
    manifest = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in identity_paths}
    (output/'INPUTS.json').write_text(json.dumps(dict(host=platform.platform(),
        machine=platform.machine(), sources=manifest), indent=2)+'\n')
    includes = ['-I'+str(source/path) for path in ['include', 'src', 'third_party/blake3']]
    definitions = ['-D'+name for name in ['BLAKE3_NO_SSE2', 'BLAKE3_NO_SSE41',
        'BLAKE3_NO_AVX2', 'BLAKE3_NO_AVX512', 'BLAKE3_USE_NEON=0']]
    objects = []
    try:
        run('compiler', [args.cxx, '--version'])
        for path in inputs[:3]:
            obj = output/(path.stem+'.o')
            run(path.stem, [args.cc, '-O2', '-DNDEBUG', '-std=c99', *includes,
                *definitions, '-c', str(path), '-o', str(obj)])
            objects.append(str(obj))
        binary = output/'meepow-kat-v2-api'
        run('link', [args.cxx, '-O2', '-DNDEBUG', '-std=c++17', '-pthread', *includes,
            *map(str, inputs[3:6]), *objects, '-o', str(binary)])
        run('kat', [str(binary), str(source/'vectors/vectors_v2.txt')])
        math_binary = output/'meepow-target-math'
        run('target-link', [args.cxx, '-O2', '-std=c++17', *includes,
            str(inputs[6]), '-o', str(math_binary)])
        run('target-math', [str(math_binary)])
        result = dict(status='PORTABLE_NATIVE_V2_KAT_PASS', host=platform.platform(),
            machine=platform.machine(), binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            vectors=20, targetQuotientChecks=10193, receipts=receipts, publicExposure=False)
        (output/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result))
    finally:
        (output/'COMMANDS.json').write_text(json.dumps(receipts, indent=2)+'\n')

if __name__ == '__main__':
    main()
