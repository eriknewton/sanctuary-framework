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

NODE_CHILD = r'''
const fs = require('node:fs'), net = require('node:net');
const {pathToFileURL} = require('node:url');
(async()=>{
  const root=__dirname, repo=REPO, scenario=SCENARIO;
  fs.writeFileSync(root+'/child.pid',String(process.pid));
  const {register}=await import(pathToFileURL(repo+'/server/node_modules/tsx/dist/esm/api/index.mjs')); register();
  const load=p=>import(pathToFileURL(repo+'/server/'+p));
  const {HermesBridgeCore}=await load('src/hermes-memory-bridge/bridge-core.ts');
  const {parseRelayToNode,encodeNodeToRelay}=await load('src/hermes-memory-bridge/envelopes.ts');
  const channel=new net.Socket({fd:3});
  const log=x=>fs.appendFileSync(root+'/events.jsonl',JSON.stringify(x)+'\n');
  const passage={passage_id:'seed',owner_ref:'hermes',text:'Cedar lantern fixture text',tags:[],metadata:[],created_at:'2026-10-18T00:00:00.000Z',chunk_count:1,content_hash:'a'.repeat(43),provenance_status:'verified'};
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
    ownerSurface:{promptOwner(){log({pending:true});}},abort:new AbortController(),
    adapter:{
      async insertPassage(){log({unexpectedInsert:true});throw Error('write unavailable');},
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
      const parsed=parseRelayToNode(bytes);if(parsed.kind!=='ok')throw Error('fixture invalid frame');core.relayFrame(parsed.frame);if(raw.type==='frame' && JSON.parse(Buffer.from(raw.frame_b64,'base64')).type==='cancel')log({cancelPending:!!core.snapshot().ledger.entry});
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
net.Socket.prototype.connect=function(...args){
  if(args[0]==='/Library/Application Support/Sanctuary/HermesMemoryBridge/sockets/memory.sock') args[0]=SOCKET;
  return originalConnect.apply(this,args);
};
fs.write=function(fd,buffer,...args){
  const callback=args.at(-1);
  if(fd===1){
    if(SCENARIO==='stdout_stall' && outputLines>=1) {const e=Object.assign(Error('fixture pressure'),{code:'EAGAIN'});queueMicrotask(()=>callback(e,0,buffer));return;}
    outputLines++;
  }
  if(fd!==1 && buffer.length>4){
    let frame;try{frame=JSON.parse(buffer.subarray(4));}catch{}
    if(frame?.type==='tools_call'){
      callWritten=true;
      if(SCENARIO==='async_failure') queueMicrotask(()=>Promise.reject(Error('fixture rejection')));
      if(SCENARIO==='short_write') return originalWrite.call(this,fd,buffer.subarray(0,buffer.length-1),...args);
      if(SCENARIO==='pong' && !extra){
        extra=true;
        const body=Buffer.from('{"type":"ping"}'),prefix=Buffer.alloc(4);prefix.writeUInt32BE(body.length);
        const combined=Buffer.concat([buffer,prefix,body]);
        return originalWrite.call(this,fd,combined,(error)=>callback(error,buffer.length,buffer));
      }
    }
  }
  return originalWrite.call(this,fd,buffer,...args);
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
    (root/'preload.cjs').write_text(PRELOAD.replace('SOCKET', json.dumps(str(root/'memory.sock'))).replace('SCENARIO', json.dumps(arm)))
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
    try:
        deadline = time.monotonic()+10
        while not (root/'memory.sock').exists():
            if native.poll() is not None or time.monotonic()>deadline:
                raise AssertionError('nativeRelayReady: '+(root/'native.log').read_text()+' '+(root/'bridge.log').read_text()+' '+(root/'relay.log').read_text())
            await anyio.sleep(0.02)
        params = StdioServerParameters(command=args.node,args=['--require',str(root/'preload.cjs'),str(repo/'server/dist/cli.js'),'hermes-memory-client'],
            env={'HOME':str(root),'SANCTUARY_NO_UPDATE_CHECK':'1'})
        with open(root/'shim-stderr','w') as errlog:
            async with stdio.stdio_client(params,errlog=errlog) as (read,write):
                async with ClientSession(read,write) as session:
                    await session.initialize()
                    if arm=='done':
                        tools=await session.list_tools()
                        assert [t.name for t in tools.tools]==['memory_insert','memory_get','memory_search'],'clientCatalogComesFromRealBridge'
                        search=await session.call_tool('memory_search',{'text':'Cedar'})
                        result=await session.call_tool('memory_get',{'passage_id':'seed'})
                        assert 'Cedar lantern fixture text' in result.content[0].text,'realClientExactGet'
                        assert 'seed' in search.content[0].text,'realClientSeededSearch'
                        try:
                            await session.call_tool('memory_get',{'passage_id':'seed','approved':True})
                            raise AssertionError('unknownArgumentsNeverReachAdapter')
                        except McpError as exc:
                            assert exc.error.code==-32002,'unknownArgumentsNeverReachAdapter'
                        events=[json.loads(line) for line in (root/'events.jsonl').read_text().splitlines()]
                        assert sum('get' in row for row in events)==1,'unknownArgumentsNeverReachAdapter'
                    elif arm=='cancel':
                        task=asyncio.create_task(session.call_tool('memory_insert',{'text':'pending fixture','taint':'user_content'}))
                        deadline=time.monotonic()+10
                        while '"pending":true' not in (root/'events.jsonl').read_text():
                            assert time.monotonic()<deadline,'pendingInsertAdmission'
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
                        assert not any(row.get('unexpectedInsert') for row in events),'clientCancelTargetsOriginalCall zero writes'
                        calls=[row['public'] for row in events if row.get('public',{}).get('type')=='tools_call']
                        cancels=[row['public'] for row in events if row.get('public',{}).get('type')=='cancel']
                        assert len(cancels)==1 and cancels[0]['mcp_request_id']==calls[0]['request_id'],'clientCancelTargetsOriginalCall exact wire'
                    elif arm=='eof':
                        before=len(capture)
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
                        expected={'oversize':-32602,'depth':-32602,'malformed':-32700,'buffered':-32700,
                            'malformed_relay':-32603,'pong':-32603,'async_failure':-32603,'socket_loss':-32004,'short_write':-32004,
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
        ids=[row['id'] for row in observed['responses']]
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
