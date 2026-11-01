"""Pinned SDK consumer against the real CLI and native relay with disposable ports."""
import argparse
import asyncio
import contextlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

import anyio
from anyio.abc import ByteReceiveStream, ByteSendStream
from mcp import ClientSession, StdioServerParameters
from mcp.client import stdio
from mcp.shared.exceptions import McpError

# Must match SHIM_STDIN_EOF_EXIT_MS in protocol.ts: SDK grace minus exit reserve.
EOF_GRACE_SECONDS = (2000 - 500) / 1000

NODE_CHILD = r'''
const fs = require('node:fs'), net = require('node:net');
const {pathToFileURL} = require('node:url');
(async()=>{
  const root=__dirname, repo=REPO, scenario=SCENARIO;
  fs.writeFileSync(root+'/child.pid',String(process.pid));
  const {register}=await import(pathToFileURL(repo+'/server/node_modules/tsx/dist/esm/api/index.mjs')); register();
  const load=p=>import(pathToFileURL(repo+'/server/'+p));
  const {HermesBridgeCore}=await load('src/hermes-memory-bridge/bridge-core.ts');
  const {hermesBridgePassageTextDigest}=await load('src/sdw/adapters/sdw-memory-backend.ts');
  const {memoryGetSuccessFrameUtf8Bytes}=await load('src/sdw/memory-tool-projection.ts');
  const {parseRelayToNode,encodeNodeToRelay}=await load('src/hermes-memory-bridge/envelopes.ts');
  const channel=new net.Socket({fd:3});
  const log=x=>fs.appendFileSync(root+'/events.jsonl',JSON.stringify(x)+'\n');
  const passage={passage_id:'seed',owner_ref:'hermes',text:'Cedar lantern fixture text',tags:[],metadata:[],created_at:'2026-10-18T00:00:00.000Z',chunk_count:1,content_hash:'a'.repeat(43),provenance_status:'verified'};
  let releaseInsert;
  const core=new HermesBridgeCore({
    writeFrame(frame){
      if(frame.type==='response' && ['malformed_relay','unavailable'].includes(scenario)) {
        const publicFrame=JSON.parse(Buffer.from(frame.publicPayloadBytes));
        if(publicFrame.type==='result' && publicFrame.payload.content) {
          const changed=scenario==='malformed_relay'?{...publicFrame,payload:[]}:{type:'error',request_id:publicFrame.request_id,message:'Memory service unavailable.'};
          const body=Buffer.from(JSON.stringify({type:'response',connection_id:frame.connectionId,request_id:frame.requestId,result_b64:Buffer.from(JSON.stringify(changed)).toString('base64')}));
          const prefix=Buffer.alloc(4);prefix.writeUInt32BE(body.length);channel.write(Buffer.concat([prefix,body]));return;
        }
      }
      channel.write(encodeNodeToRelay(frame));
    },
    appendAudit:async record=>log({audit:record}),nowMs:()=>Date.now(),
    setTimer:(ms,fire)=>setTimeout(fire,ms),clearTimer:timer=>clearTimeout(timer),
    agentId:"hermes",abort:new AbortController(),
    adapter:{
      async recallPassages(budget){return budget.result();},
      async insertPassage(input){
        log({insertStarted:true});
        if(scenario==='cancel')await new Promise(resolve=>releaseInsert=resolve);
        const inserted={...passage,passage_id:'pending',text:input.text};
        await core.commitCheck.assertAllowedToCommit({passageId:inserted.passage_id,documentId:'mem.hermes.pending',
          passageTextSha256:hermesBridgePassageTextDigest(input.text),passageTextUtf8:Buffer.from(input.text),
          getFrameUtf8Bytes:memoryGetSuccessFrameUtf8Bytes(inserted)});
        log({committed:true});return inserted;
      },
      async getPassage(id){
        log({get:id});
        if(['deadline','signal','eof','socket_loss','buffered','malformed','pong','cancel','async_failure'].includes(scenario)) return new Promise(()=>{});
        return id==='seed'?passage:null;
      },
      async searchPassages(query){log({search:query});return [{passage,match_count:1}];}
    }
  });
  let tail=Buffer.alloc(0);
  channel.on('data',chunk=>{
    tail=Buffer.concat([tail,chunk]);
    while(tail.length>=4 && tail.length>=4+tail.readUInt32BE()) {
      const n=tail.readUInt32BE(),bytes=tail.subarray(4,4+n);tail=tail.subarray(4+n);
      const raw=JSON.parse(bytes);log({relay:raw.type});
      if(raw.type==='frame') {
        const f=JSON.parse(Buffer.from(raw.frame_b64,'base64'));log({public:f});
        if(f.type==='tools_call' && scenario==='socket_loss') {
          channel.write(encodeNodeToRelay({type:'close',connectionId:raw.connection_id}));continue;
        }
      }
      const parsed=parseRelayToNode(bytes);if(parsed.kind!=='ok')throw Error('fixture invalid frame');core.relayFrame(parsed.frame);if(raw.type==='frame' && JSON.parse(Buffer.from(raw.frame_b64,'base64')).type==='cancel'){releaseInsert?.();setImmediate(()=>log({cancelPending:!!core.snapshot().ledger.entry}));}
      if(raw.type==='relay_shutdown') {channel.end();setTimeout(()=>process.exit(0),20);}
    }
  });
  channel.on('end',()=>{core.relayEof();process.exit(0);});
  channel.on('error',()=>process.exit(1));
  channel.write(encodeNodeToRelay({type:'ready'}));
})().catch(error=>{console.error(error);process.exit(1);});
'''

PRELOAD = r'''
const fs=require('node:fs'),net=require('node:net'),{syncBuiltinESMExports}=require('node:module');
const originalConnect=net.Socket.prototype.connect,originalWrite=fs.write;
let outputLines=0,callWritten=false,extra=false;
const root=__dirname;
const log=x=>fs.appendFileSync(root+'/native-io.jsonl',JSON.stringify(x)+'\n');
if(['stdout_eof','stdout_signal'].includes(SCENARIO)) {
  process.stdin.on('end',()=>fs.writeFileSync(root+'/silent','eof'));
  process.on('SIGTERM',()=>fs.writeFileSync(root+'/silent','signal'));
}
net.Socket.prototype.connect=function(...args){
  if(args[0]==='/Library/Application Support/Sanctuary/HermesMemoryBridge/sockets/memory.sock') args[0]=SOCKET;
  return originalConnect.apply(this,args);
};
fs.write=function(fd,buffer,...args){
  const callback=args.at(-1);
  if(fd===1 && ['stdout_eof','stdout_signal'].includes(SCENARIO) && outputLines>=1 && !extra) {
    extra=true;
    // Fill the actual pipe until the kernel refuses bytes, before the selected reply write.
    const fill=Buffer.alloc(1024,120);let count=0;
    for(;;) {try {count+=fs.writeSync(fd,fill);}catch(error){if(error.code!=='EAGAIN')throw error;break;}}
    fs.writeFileSync(root+'/filled',String(count));
  }
  if(fd===1 && ['stdout_eof','stdout_signal'].includes(SCENARIO)) {
    outputLines++;
    return originalWrite.call(this,fd,buffer,(error,written)=>{
      log({stdout:true,error:error?.code,written,silent:fs.existsSync(root+'/silent')});
      if(error?.code==='EAGAIN')fs.writeFileSync(root+'/eagain','yes');
      callback(error,written,buffer);
    });
  }
  if(fd===1){
    if(SCENARIO==='stdout_stall' && outputLines>=1) {const e=Object.assign(Error('fixture pressure'),{code:'EAGAIN'});queueMicrotask(()=>callback(e,0,buffer));return;}
    outputLines++;
  }
  if(fd!==1 && buffer.length>4){
    let frame;try{frame=JSON.parse(buffer.subarray(4));}catch{}
    if(frame?.type==='shutdown' && ['stdout_eof','stdout_signal'].includes(SCENARIO)) {
      // 500 ms = SDK process grace (2000) minus shim EOF bound (1500).
      setTimeout(()=>originalWrite.call(this,fd,buffer,...args),500);return;
    }
    if(frame?.type==='tools_call'){
      callWritten=true;
      if(SCENARIO==='relay_eagain' && !extra) {
        extra=true;let count=0;const padding=Buffer.alloc(1024);
        for(;;){try{count+=fs.writeSync(fd,padding);}catch(error){if(error.code!=='EAGAIN')throw error;break;}}
        fs.writeFileSync(root+'/prefill',String(count));
      }
      if(SCENARIO==='async_failure') queueMicrotask(()=>Promise.reject(Error('fixture rejection')));
      if(SCENARIO==='short_write') return originalWrite.call(this,fd,buffer.subarray(0,buffer.length-1),(error,written)=>callback(error||Object.assign(Error('fixture transport'),{code:'EPIPE'}),written,buffer));
      if(SCENARIO==='pong' && !extra){
        extra=true;
        const body=Buffer.from('{"type":"ping"}'),prefix=Buffer.alloc(4);prefix.writeUInt32BE(body.length);
        const combined=Buffer.concat([buffer,prefix,body]);
        return originalWrite.call(this,fd,combined,(error)=>callback(error,buffer.length,buffer));
      }
    }
  }
  return originalWrite.call(this,fd,buffer,(error,written)=>{
    if(fd!==1)log({relay:true,length:buffer.length,error:error?.code,written});
    callback(error,written,buffer);
  });
};
syncBuiltinESMExports();
'''

class CaptureReceive(ByteReceiveStream):
    def __init__(self, stream, evidence):
        self.stream, self.evidence = stream, evidence
    async def receive(self, max_bytes=65536):
        data = await self.stream.receive(max_bytes)
        self.evidence.extend(data)
        return data
    async def aclose(self):
        await self.stream.aclose()

class CaptureSend(ByteSendStream):
    def __init__(self, stream, evidence, arm):
        self.stream, self.evidence, self.arm = stream, evidence, arm
        self.pending = None
    async def send(self, data):
        self.evidence.extend(data)
        value = json.loads(data)
        if self.arm == 'buffered' and value.get('method') == 'ping' and self.pending:
            await self.stream.send(self.pending + b'bad\n' + data)
            self.pending = None
            return
        if value.get('method') == 'tools/call':
            if self.arm == 'malformed':
                await self.stream.send(data + b'bad\n')
                return
            if self.arm == 'buffered':
                self.pending = data
                return
        await self.stream.send(data)
    async def aclose(self):
        await self.stream.aclose()

class CaptureProcess:
    def __init__(self, process, stdout, stdin):
        self.process, self.stdout, self.stdin = process, stdout, stdin
    def __getattr__(self, name):
        return getattr(self.process, name)
    async def __aenter__(self):
        await self.process.__aenter__()
        return self
    async def __aexit__(self, *args):
        return await self.process.__aexit__(*args)

async def run(args, root):
    assert importlib.metadata.version('mcp') == '1.26.0', 'pinnedPythonClientVersion'
    repo = Path(args.repo)
    arm = args.arm
    (root/'child.cjs').write_text(NODE_CHILD.replace('REPO', json.dumps(str(repo))).replace('SCENARIO', json.dumps(arm)))
    (root/'preload.cjs').write_text(PRELOAD.replace('SOCKET', json.dumps(str(root/('proxy.sock' if arm=='relay_eagain' else 'memory.sock')))).replace('SCENARIO', json.dumps(arm)))
    config = dict(schema_version=1,node_executable=args.node,node_entry=str(root/'child.cjs'),bridge_log=str(root/'bridge.log'),
                  relay_log=str(root/'relay.log'),public_socket=str(root/'memory.sock'),private_dir=str(root),owner_uid=501,
                  hermes_account='fixture',hermes_uid=502,group='fixture',fortress_id='hermes-memory',agent_id='hermes',identity_fingerprint='a'*64)
    (root/'relay-config.json').write_text(json.dumps(config))
    relay_log = open(root/'native.log','w')
    native = subprocess.Popen(['/usr/bin/xcrun','xctest','-XCTest',
        'HermesMemoryRelayCoreTests.RuntimeContractTests/testRealChildReadyFollowsComposition',args.bundle],
        env={**os.environ,'HOME':str(root),'HMR_ENTRYPOINT_FIXTURE':str(root)},stdout=relay_log,stderr=subprocess.STDOUT)
    capture = bytearray(); sent = bytearray(); shim_process = None
    original = stdio._create_platform_compatible_process
    async def create(**kwargs):
        nonlocal shim_process
        proc = await original(**kwargs)
        shim_process = proc
        return CaptureProcess(proc,CaptureReceive(proc.stdout,capture),CaptureSend(proc.stdin,sent,arm))
    stdio._create_platform_compatible_process = create
    observed = {'arm':arm,'exceptions':[],'responses':[]}
    proxy = None; proxy_tasks = set()
    async def delayed_peer(reader, writer):
        current=asyncio.current_task();proxy_tasks.add(current)
        remote_writer=None
        try:
            remote_reader,remote_writer=await asyncio.open_unix_connection(str(root/'memory.sock'))
            async def downstream():
                while data:=await remote_reader.read(65540):
                    writer.write(data);await writer.drain()
            downstream_task=asyncio.create_task(downstream());proxy_tasks.add(downstream_task)
            prefix=await reader.readexactly(4)
            hello=await reader.readexactly(int.from_bytes(prefix,'big'))
            reader._transport.pause_reading()
            remote_writer.write(prefix+hello);await remote_writer.drain()
            while not (root/'prefill').exists(): await asyncio.sleep(0.01)
            # The fixture peer delays reading until the first native call write sees a full socket.
            await asyncio.sleep(0.1)
            reader._transport.resume_reading()
            padding=await reader.readexactly(int((root/'prefill').read_text()))
            assert not any(padding),'relayEagainFixturePadding'
            while data:=await reader.read(65540):
                remote_writer.write(data);await remote_writer.drain()
        finally:
            writer.close()
            if remote_writer: remote_writer.close()
            proxy_tasks.discard(current)
    try:
        deadline = time.monotonic()+10
        while not (root/'memory.sock').exists():
            if native.poll() is not None or time.monotonic()>deadline:
                raise AssertionError('nativeRelayReady: '+(root/'native.log').read_text()+' '+(root/'bridge.log').read_text()+' '+(root/'relay.log').read_text())
            await anyio.sleep(0.02)
        if arm=='relay_eagain': proxy=await asyncio.start_unix_server(delayed_peer,str(root/'proxy.sock'),limit=131080)
        params = StdioServerParameters(command=args.node,args=['--require',str(root/'preload.cjs'),str(repo/'server/dist/cli.js'),'hermes-memory-client'],
            env={'HOME':str(root),'SANCTUARY_NO_UPDATE_CHECK':'1'})
        if arm in ('stdout_eof','stdout_signal'):
            return await raw_silent_pipe(args,root,params)
        with open(root/'shim-stderr','w') as errlog:
            async with stdio.stdio_client(params,errlog=errlog) as (read,write):
                async with ClientSession(read,write) as session:
                    await session.initialize()
                    if arm=='done':
                        tools=await session.list_tools()
                        assert [t.name for t in tools.tools]==['memory_insert','memory_get','memory_search','memory_recall','sign_statement','export_memory','protection_rules'],'clientCatalogComesFromRealBridge'
                        search=await session.call_tool('memory_search',{'text':'Cedar'})
                        result=await session.call_tool('memory_get',{'passage_id':'seed'})
                        assert 'Cedar lantern fixture text' in result.content[0].text,'realClientExactGet'
                        assert 'seed' in search.content[0].text,'realClientSeededSearch'
                        denied=await session.call_tool('memory_get',{'passage_id':'seed','approved':True})
                        assert json.loads(denied.content[0].text)=={'outcome':'denied','message':'Request denied.'},'unknownArgumentsNeverReachAdapter'
                        events=[json.loads(line) for line in (root/'events.jsonl').read_text().splitlines()]
                        assert sum('get' in row for row in events)==1,'unknownArgumentsNeverReachAdapter'
                    elif arm in ('large_frames','relay_eagain'):
                        sizes = [9000, 65536 + 4] if arm=='large_frames' else [9000]
                        for size in sizes:
                            # 35 bytes = r + 32 hex + dot + one serial digit, for these first calls.
                            envelope={'type':'tools_call','request_id':'r'+'a'*32+'.2','name':'memory_search','arguments':{'text':''}}
                            length=size-4-len(json.dumps(envelope,separators=(',',':')).encode())
                            try: result=await session.call_tool('memory_search',{'text':'x'*length})
                            except McpError as exc: raise AssertionError('realRelayLargeFramesSettle: '+str(exc)) from exc
                            assert 'seed' in result.content[0].text,'realRelayLargeFramesSettle'
                        events=[json.loads(line) for line in (root/'events.jsonl').read_text().splitlines()]
                        frames=[row['public'] for row in events if row.get('public',{}).get('type')=='tools_call']
                        assert [4+len(json.dumps(frame,separators=(',',':')).encode()) for frame in frames]==sizes,'realRelayExactFrameSizes'
                        io=[json.loads(line) for line in (root/'native-io.jsonl').read_text().splitlines()]
                        observed['native_writes']=io
                        if arm=='relay_eagain':
                            assert next(row for row in io if row.get('length')==9000).get('error')=='EAGAIN','realRelayFirstWriteEagain'
                    elif arm=='cancel':
                        task=asyncio.create_task(session.call_tool('memory_insert',{'text':'pending fixture','taint':'user_content'}))
                        deadline=time.monotonic()+10
                        while '"insertStarted":true' not in (root/'events.jsonl').read_text():
                            assert time.monotonic()<deadline,'insertAdmissionBeforeCommit'
                            await anyio.sleep(0.01)
                        cancel=json.dumps({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':1}}).encode()+b'\n'
                        await shim_process.stdin.send(cancel)
                        while '"cancelPending":false' not in (root/'events.jsonl').read_text():
                            assert time.monotonic()<deadline,'clientCancelTargetsOriginalCall'
                            await anyio.sleep(0.01)
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError): await task
                        await session.send_ping()
                        events=[json.loads(line) for line in (root/'events.jsonl').read_text().splitlines()]
                        assert not any(row.get('committed') for row in events),'clientCancelTargetsOriginalCall zero writes'
                        calls=[row['public'] for row in events if row.get('public',{}).get('type')=='tools_call']
                        cancels=[row['public'] for row in events if row.get('public',{}).get('type')=='cancel']
                        assert len(cancels)==1 and cancels[0]['mcp_request_id']==calls[0]['request_id'],'clientCancelTargetsOriginalCall exact wire'
                    elif arm=='eof':
                        task=asyncio.create_task(session.call_tool('memory_get',{'passage_id':'seed'}))
                        deadline=time.monotonic()+10
                        while '"get":"seed"' not in (root/'events.jsonl').read_text():
                            assert time.monotonic()<deadline,'realEofAdmission'
                            await anyio.sleep(0.01)
                        before=len(capture); started=time.monotonic()
                        await shim_process.stdin.aclose()
                        with anyio.move_on_after(EOF_GRACE_SECONDS) as scope:
                            await shim_process.wait()
                        exited_in_grace = not scope.cancel_called
                        if not exited_in_grace:
                            # Reap a failed fixture before SDK context teardown can mask the timed assertion.
                            task.cancel()
                            with contextlib.suppress(asyncio.CancelledError, McpError): await task
                            shim_process.kill()
                            with anyio.fail_after(5): await shim_process.wait()
                        assert exited_in_grace,'realEofExitsWithinGrace'
                        observed['eof_exit_ms']=(time.monotonic()-started)*1000
                        assert len(capture)==before,'realEofNoStdout'
                        try: await task
                        except McpError as exc:
                            observed['exceptions'].append({'code':exc.error.code,'message':exc.error.message})
                    else:
                        async def signal_after_admission():
                            deadline=time.monotonic()+10
                            while '"get":"seed"' not in (root/'events.jsonl').read_text():
                                assert time.monotonic()<deadline,'signalAdmission'
                                await anyio.sleep(0.01)
                            os.kill(shim_process.pid,signal.SIGTERM)
                        task = asyncio.create_task(signal_after_admission()) if arm=='signal' else None
                        arguments={'passage_id':'seed'}
                        if arm=='oversize': arguments['ignored']='x'*70000
                        if arm=='depth':
                            nested=0
                            for _ in range(70): nested=[nested]
                            arguments['ignored']=nested
                        try:
                            if arm=='buffered':
                                async def request_call():
                                    try: await session.call_tool('memory_get',arguments)
                                    except McpError as exc: return {'code':exc.error.code,'message':exc.error.message}
                                async def request_ping():
                                    try: await session.send_ping()
                                    except McpError as exc: return {'code':exc.error.code,'message':exc.error.message}
                                errors=await asyncio.gather(request_call(),request_ping())
                                observed['exceptions'].extend(errors)
                            else:
                                await session.call_tool('memory_get',arguments)
                        except McpError as exc:
                            observed['exceptions'].append({'code':exc.error.code,'message':exc.error.message})
                        finally:
                            if task: await task
                        expected={'oversize':-32602,'depth':-32602,'malformed':-32004,'buffered':-32004,
                            'malformed_relay':-32004,'pong':-32004,'async_failure':-32004,'socket_loss':-32004,'short_write':-32004,
                            'deadline':-32005,'unavailable':-32004,'stdout_stall':-32000,'signal':-32000}[arm]
                        assert observed['exceptions'] and observed['exceptions'][0]['code']==expected, 'realClientArmOutcome: '+json.dumps(observed)
                        if arm in ('oversize','depth','unavailable'):
                            await session.send_ping()
            if arm=='eof': assert len(capture)==before,'eofAndSignalProduceNoNewStdout'
        if arm=='done':
            # The SDK allocates integer IDs. A raw second stdio peer checks string IDs
            # and proves that the first peer's shutdown left the relay available.
            with open(root/'shim-stderr','a') as errlog:
                async with stdio.stdio_client(params,errlog=errlog) as (read,write):
                    async def raw_request(value):
                        data=json.dumps(value).encode()+b'\n'
                        sent.extend(data)
                        await shim_process.stdin.send(data)
                    await raw_request({'jsonrpc':'2.0','method':'initialize','params':{
                        'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'raw-fixture','version':'1'}},'id':'raw-init'})
                    initialized=await read.receive()
                    assert initialized.message.root.id=='raw-init','rawTypedIdsInitialize'
                    await raw_request({'jsonrpc':'2.0','method':'notifications/initialized'})
                    for request_id in (10,'10'):
                        await raw_request({'jsonrpc':'2.0','method':'tools/call','params':{
                            'name':'memory_get','arguments':{'passage_id':'seed'}},'id':request_id})
                    replies=[(await read.receive()).message.root for _ in range(2)]
                    assert {(type(reply.id).__name__,str(reply.id)) for reply in replies}=={('int','10'),('str','10')},'rawTypedIdsStayDistinct'
                    numeric=next(reply for reply in replies if isinstance(reply.id,int))
                    assert 'Cedar lantern fixture text' in numeric.result['content'][0]['text'],'clientShutdownCancelsOnlyItsConnection'
            observed['raw_stdio']='numeric 10 and string 10 remain distinct after prior peer shutdown'
        assert (root/'shim-stderr').stat().st_size==0,'contentFreeStderr'
        observed['responses']=[json.loads(line) for line in capture.splitlines()]
        observed['stdout_hex']=capture.hex()
        observed['stdin_ids']=[json.loads(line).get('id') for line in sent.splitlines() if 'id' in json.loads(line)]
        ids=[row['id'] for row in observed['responses'] if row['id'] is not None]
        assert len(ids)==len(set(ids)),'exactlyOneResponsePerId'
        if arm=='buffered': assert 2 in ids,'bufferedUnreadIdsDrainBeforeClose'
        if arm not in ('eof','signal','stdout_stall','done','cancel'):
            assert 1 in ids,'correlatedErrorBeforeEof'
        if arm=='signal':
            observed['acceptance']='UNPROVEN: OB14 silent signal leaves an active SDK request reporting Connection closed'
        elif arm=='stdout_stall':
            observed['acceptance']='PASS: dead stdout residual produces SDK Connection closed'
        else: observed['acceptance']='PASS'
        return observed
    finally:
        if proxy:
            proxy.close();await proxy.wait_closed()
        for task in proxy_tasks: task.cancel()
        if proxy_tasks: await asyncio.gather(*list(proxy_tasks),return_exceptions=True)
        stdio._create_platform_compatible_process=original
        try:
            with anyio.CancelScope(shield=True):
                if shim_process and shim_process.returncode is None:
                    shim_process.kill()
                    with anyio.fail_after(5): await shim_process.wait()
        finally:
            native.terminate()
            try: native.wait(timeout=8)
            except subprocess.TimeoutExpired:
                native.kill();native.wait(timeout=3)
            relay_log.close()
            if (root/'child.pid').exists():
                child_pid=int((root/'child.pid').read_text())
                try: os.kill(child_pid,0)
                except ProcessLookupError: pass
                else: raise AssertionError('nativeRelayMustReapChild')

async def raw_silent_pipe(args, root, params):
    """Raw pipes are necessary because the SDK continuously drains its stdout reader."""
    proc=await asyncio.create_subprocess_exec(args.node,*params.args,stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env={**os.environ,'HOME':str(root)})
    # Pause asyncio's reader too; it otherwise silently drains the kernel pipe into its own buffer.
    transport=proc.stdout._transport
    try:
        initialize={'jsonrpc':'2.0','method':'initialize','params':{'protocolVersion':'2025-11-25',
            'capabilities':{},'clientInfo':{'name':'raw','version':'1'}},'id':0}
        proc.stdin.write(json.dumps(initialize).encode()+b'\n');await proc.stdin.drain()
        response=await proc.stdout.readline();assert json.loads(response)['id']==0,'rawSilentInitialize'
        transport.pause_reading()
        proc.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}).encode()+b'\n')
        proc.stdin.write(json.dumps({'jsonrpc':'2.0','method':'tools/call','params':{'name':'memory_get',
            'arguments':{'passage_id':'seed'}},'id':1}).encode()+b'\n');await proc.stdin.drain()
        async def marker(name):
            deadline=time.monotonic()+5
            while not (root/name).exists():
                assert time.monotonic()<deadline,'rawSilentMarker '+name
                await asyncio.sleep(0.005)
        await marker('eagain')
        started=time.monotonic()
        if args.arm=='stdout_eof': proc.stdin.close();await proc.stdin.wait_closed()
        else: proc.send_signal(signal.SIGTERM)
        await marker('silent')
        # Bytes already accepted before the event are filler only; draining now makes stdout writable.
        transport.resume_reading()
        output=await proc.stdout.read()
        await proc.wait()
        assert time.monotonic()-started < EOF_GRACE_SECONDS,'silentPipeExitWithinGrace'
        count=int((root/'filled').read_text())
        assert output==b'x'*count,'silentPipeNoBytesAfterStop'
        io=[json.loads(line) for line in (root/'native-io.jsonl').read_text().splitlines()]
        assert not any(row.get('silent') and row.get('written',0)>0 for row in io),'silentPipeNoNativeWriteAfterStop'
        assert await proc.stderr.read()==b'','rawSilentContentFreeStderr'
        return {'arm':args.arm,'acceptance':'PASS','filler_bytes':count,'post_stop_bytes':len(output)-count,'native_writes':io}
    finally:
        transport.resume_reading()
        if proc.returncode is None: proc.kill();await proc.wait()

async def bounded_run(args, root):
    # A wrapper timeout cancels the task so both process cleanup paths still run.
    loop=asyncio.get_running_loop()
    task=asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM,task.cancel)
    try:
        with anyio.fail_after(140):
            return await run(args,root)
    finally:
        loop.remove_signal_handler(signal.SIGTERM)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo',required=True);parser.add_argument('--node',required=True)
    parser.add_argument('--bundle',required=True);parser.add_argument('--arm',required=True)
    args=parser.parse_args()
    root=Path(tempfile.mkdtemp(prefix='hmc-',dir='/tmp'));os.chmod(root,0o700)
    try:
        observation=anyio.run(bounded_run,args,root)
        print(json.dumps(observation))
    finally:
        # Harness owns only this newly created root; no operator state is used.
        import shutil
        shutil.rmtree(root)
