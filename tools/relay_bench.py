import json, os, socket, subprocess, tempfile, threading, time, statistics, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
CPU=str(min(os.sched_getaffinity(0)))
def run(binary, mode, count_syscalls=False):
    backend=socket.socket();backend.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);backend.bind(('127.0.0.1',0));backend.listen()
    up=backend.getsockname()[1]
    pub=socket.socket();pub.bind(('127.0.0.1',0));port=pub.getsockname()[1];pub.close()
    errors=[]
    bulk=b'X'*(32*1024*1024)
    def serve():
        try:
            conn,_=backend.accept()
            with conn:
                conn.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                if mode=='bulk':
                    assert conn.recv(1)==b'X'
                    conn.sendall(bulk)
                else:
                    while True:
                        data=conn.recv(65536)
                        if not data:break
                        conn.sendall(data)
        except BaseException as e: errors.append(str(e))
        finally:backend.close()
    t=threading.Thread(target=serve,daemon=True);t.start()
    with tempfile.TemporaryDirectory() as directory:
        conf=Path(directory)/'vane.json';cnt=Path(directory)/'counts.json'
        conf.write_text(json.dumps({'logging':{'level':'error'},'listeners':[{'transport':'tcp','address':f'127.0.0.1:{port}','targets':[{'location':f'127.0.0.1:{up}'}]}]}))
        env=os.environ.copy()
        if count_syscalls:env.update(LD_PRELOAD=str(ROOT/'epoll_counter.so'),VANE_EPOLL_COUNTS=str(cnt))
        process=subprocess.Popen(['taskset','-c',CPU,str(binary),str(conf)],stderr=subprocess.PIPE,env=env)
        try:
            # Retry connect without sending data: first successful connection is
            # the measured connection, so no backend readiness connection exists.
            deadline=time.monotonic()+3
            while True:
                try:client=socket.create_connection(('127.0.0.1',port),timeout=2);break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.01)
            with client:
                client.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);client.settimeout(5)
                if mode=='bulk':
                    start=time.perf_counter();client.sendall(b'X');got=0
                    while got<len(bulk):
                        data=client.recv(262144)
                        if not data:raise RuntimeError('short bulk')
                        got+=len(data)
                    result={'MiB_s':32/(time.perf_counter()-start)}
                else:
                    times=[]
                    for i in range(5200):
                        start=time.perf_counter_ns();client.sendall(b'x'*64);got=0
                        while got<64:got+=len(client.recv(64-got))
                        if i>=200:times.append((time.perf_counter_ns()-start)/1000)
                    times.sort();result={'p50_us':statistics.median(times),'p99_us':times[int(len(times)*.99)]}
            t.join(3)
            if errors:raise RuntimeError(errors)
        finally:
            process.terminate();_,err=process.communicate(timeout=3)
            if process.returncode:raise RuntimeError(err)
        if count_syscalls:result.update(json.loads(cnt.read_text()))
    return result
if len(sys.argv) != 4:
    raise SystemExit("usage: relay_bench.py OLD_BINARY NEW_BINARY OUTPUT_JSONL")
old, new = (Path(arg).resolve() for arg in sys.argv[1:3])
with open(sys.argv[3], 'w') as f:
    for mode in ('ping','bulk'):
        for n in range(5):
            for label,binary in (('old',old),('new',new)) if n%2==0 else (('new',new),('old',old)):
                r={'mode':mode,'run':n+1,'kind':label,**run(binary,mode)}
                f.write(json.dumps(r)+'\n');f.flush()
    for label,binary in (('old',old),('new',new)):
        f.write(json.dumps({'mode':'counted_ping','kind':label,**run(binary,'ping',True)})+'\n');f.flush()
