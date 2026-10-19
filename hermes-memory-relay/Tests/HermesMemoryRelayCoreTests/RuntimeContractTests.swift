import Darwin
import Foundation
import XCTest
import MemoryGrantPeer
@testable import HermesMemoryRelayCore

// Fixture timing derives from the wire budgets: 10 ms = 2000/200; 20 ms = 2000/100;
// 4000 ms = two probe intervals; 15000 ms = three ready intervals; subprocess bounds = 2000 ms.
// The stop assertion independently pins 6000 ms = 2000 private shutdown + 3000 SIGTERM + 1000 reap.
final class RuntimeContractTests: XCTestCase {
    func testRuntimeProcessesMultipleBoundedFrames() throws {
        try nativeRun(body: Self.transportChild, expectsReady: true, witness: "runtimeProcessesMultipleBoundedFrames")
    }

    func testProbeDrainSeesCancelBeforeReply() throws {
        try nativeRun(body: Self.probeChild, expectsReady: true, witness: "probeDrainSeesCancelBeforeReply")
    }

    func testPeerAuthenticationPrecedesDecode() throws {
        try nativeRun(body: """
        channel.on('data',chunk=>{throw Error('peerAuthenticationPrecedesDecode: rejected peer reached Node');});
        channel.write(frame({type:'ready'}));
        const connect=setInterval(()=>{
          if(!fs.existsSync(socketPath)) return;
          clearInterval(connect);
          const client=net.createConnection(socketPath);
          client.on('connect',()=>client.write(Buffer.from([255,255,255,255])));
          client.on('error',()=>{});
          client.on('close',()=>{console.log('WITNESS_PASS');process.exit(0);});
        },10);
        """, expectsReady: true, witness: "peerAuthenticationPrecedesDecode", scenario: "reject-peer")
    }

    func testFifthConnectionNeverReachesNode() throws {
        try nativeRun(body: """
        const assert=require('node:assert/strict');
        let bytes=Buffer.alloc(0), accepted=0;
        channel.on('data',chunk=>{
          bytes=Buffer.concat([bytes,chunk]);
          while(bytes.length>=4 && bytes.length>=4+bytes.readUInt32BE(0)) {
            const n=bytes.readUInt32BE(0), message=JSON.parse(bytes.subarray(4,4+n)); bytes=bytes.subarray(4+n);
            if(message.type==='accepted') accepted++;
          }
        });
        channel.write(frame({type:'ready'}));
        const connect=setInterval(()=>{
          if(!fs.existsSync(socketPath)) return;
          clearInterval(connect);
          const clients=Array.from({length:5},()=>net.createConnection(socketPath));
          clients.forEach(client=>client.on('error',()=>{}));
          // One probe interval permits queued native admissions to finish without reading client data.
          setTimeout(()=>{
            assert.equal(accepted,4,'fifthConnectionNeverReachesNode');
            assert.equal(clients.filter(client=>client.destroyed).length,1,'fifthConnectionNeverReachesNode');
            clients.forEach(client=>client.destroy()); console.log('WITNESS_PASS'); process.exit(0);
          },2000);
        },10);
        """, expectsReady: true, witness: "fifthConnectionNeverReachesNode")
    }

    func testChildExitBeforeReadyNeverBinds() throws {
        try nativeRun(body: "if (fs.existsSync(socketPath)) throw Error('early bind'); console.log('WITNESS_PASS'); process.exit(0);",
                      expectsReady: false, witness: "childExitBeforeReadyNeverBinds")
    }

    func testMalformedReadyLeavesNoSocket() throws {
        try nativeRun(body: "channel.write(frame({type:'pong'})); setTimeout(()=>{ console.log('WITNESS_PASS'); process.exit(0); }, 20);",
                      expectsReady: false, witness: "malformedReadyLeavesNoSocket")
    }

    func testReadyTimeoutNeverBinds() throws {
        try nativeRun(body: """
        clearTimeout(timer);
        channel.on('data',()=>{console.log('WITNESS_PASS');process.exit(0);});
        """, expectsReady: false, witness: "readyTimeoutNeverBinds")
    }

    func testDuplicateReadyStopsRuntime() throws {
        try nativeRun(body: """
        channel.write(Buffer.concat([frame({type:'ready'}),frame({type:'ready'})]));
        console.log('WITNESS_PASS');
        """, expectsReady: false, witness: "duplicateReadyStopsRuntime")
    }

    func testSpawnDescriptorIdentityIsExact() throws {
        try nativeRun(body: """
        const assert=require('node:assert/strict');
        assert.equal(fs.fstatSync(3).isSocket(),true,'spawnDescriptorIdentityIsExact');
        const sentinel=fs.statSync(socketPath+'.sentinel');
        for(const entry of fs.readdirSync('/dev/fd')) { const fd=Number(entry); if(fd<=3) continue;
          let info; try {info=fs.fstatSync(fd);} catch {continue;}
          assert.ok(info.dev!==sentinel.dev || info.ino!==sentinel.ino,'spawnDescriptorIdentityIsExact unrelated fd');
        }
        const inherited=fs.fstatSync(3);
        const child=require('node:child_process').spawnSync(process.execPath,['-e',
          "const fs=require('node:fs');let found=false;for(const entry of fs.readdirSync('/dev/fd')){const fd=Number(entry);try{const s=fs.fstatSync(fd);if(s.isSocket()&&s.dev==process.argv[1]&&s.ino==process.argv[2])found=true;}catch{}}process.exit(found?1:0)",
          String(inherited.dev),String(inherited.ino)],{stdio:'ignore',timeout:2000});
        assert.equal(child.status,0,'spawnDescriptorIdentityIsExact descendant');
        console.log('WITNESS_PASS'); process.exit(0);
        """, expectsReady: false, witness: "spawnDescriptorIdentityIsExact")
    }

    func testSpawnUsesOnlyConfiguredEnvironment() throws {
        try nativeRun(body: """

        const expected = ['HERMES_MEMORY_AGENT_ID','HERMES_MEMORY_BRIDGE_IDENTITY','HERMES_MEMORY_FORTRESS_ID','HOME','LANG','TMPDIR'];
        if (process.platform === 'darwin') {
          expected.push('__CF_USER_TEXT_ENCODING');
          const value = process.env.__CF_USER_TEXT_ENCODING;
          if (!/^0x[0-9A-F]+:0x[0-9A-F]+:0x[0-9A-F]+$/.test(value) || value.split(':')[0] !== '0x'+process.getuid().toString(16).toUpperCase()) throw Error('invalid native encoding');
        }
        if (Object.keys(process.env).sort().join(',') !== expected.sort().join(',')) throw Error('environment differs: '+Object.keys(process.env).sort().join(','));

        console.log('WITNESS_PASS'); process.exit(0);
        """, expectsReady: false, witness: "spawnUsesOnlyConfiguredEnvironment")
    }

    func testRealCLIEnvironmentAdmission() throws {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        let cli = repository + "/server/src/cli.ts"
        let loader = repository + "/server/node_modules/tsx/dist/esm/api/index.mjs"
        let custody = repository + "/server/test/setup/keychain-memory-store.ts"
        try nativeRun(body: """
        (async()=>{
          const { pathToFileURL } = await import('node:url');
          const { register } = await import(pathToFileURL(\(quoted(loader))).href); register();
          const { installInMemoryKeychainStore } = await import(pathToFileURL(\(quoted(custody))).href);
          installInMemoryKeychainStore();
          process.argv = [process.execPath, \(quoted(cli)), 'hermes-memory-bridge', 'run', '--relay-fd', '3'];
          await import(pathToFileURL(\(quoted(cli))).href);
        })().catch(error=>{ console.error(error); process.exit(1); });
        """, expectsReady: false, witness: "realCLIEnvironmentAdmission")
    }

    func testPublicSocketWaitsForRealChildReady() throws {
        try nativeRun(body: Self.realCLIClient, expectsReady: true, witness: "publicSocketWaitsForRealChildReady", seeded: true)
    }

    func testRealChildReadyFollowsComposition() throws {
        if let root = ProcessInfo.processInfo.environment["HMR_ENTRYPOINT_FIXTURE"] {
            HermesMemoryRelayEntrypoint.run(["HermesMemoryRelay", "--config", root + "/relay-config.json"], main: { args in
                RelayRuntime.main(args, loadConfiguration: { path in
                    try RuntimeConfiguration.parse(Data(contentsOf: URL(fileURLWithPath: path)))
                }, compose: { config in self.fixtureRuntime(config, root: root) })
            })
        }
        try nativeRun(body: Self.realCLIClient, expectsReady: true, witness: "realChildReadyFollowsComposition", seeded: true)
    }

    func testCustodyRefusalLeavesNoSocket() throws {
        try nativeRun(body: Self.refusingCLI, expectsReady: false, witness: "custodyRefusalLeavesNoSocket", seeded: true,
                      scenario: "custody", expectedLog: "state_CUSTODY_PRESENT: startup refused")
    }

    func testFortressRefusalLeavesNoSocket() throws {
        try nativeRun(body: Self.refusingCLI, expectsReady: false, witness: "fortressRefusalLeavesNoSocket", seeded: true,
                      scenario: "identity", expectedLog: "state_FORTRESS_UNLOCKED: startup refused")
    }

    func testPersistedTrapPreventsRealChildReady() throws {
        try nativeRun(body: Self.refusingCLI, expectsReady: false, witness: "persistedTrapPreventsRealChildReady", seeded: true,
                      scenario: "trap", expectedLog: "state_CONFIG_CHECKED: startup refused")
    }

    func testStaleCorpusLockRefusesReady() throws {
        try nativeRun(body: Self.refusingCLI, expectsReady: false, witness: "staleCorpusLockRefusesReady", seeded: true,
                      scenario: "lock", expectedLog: "never auto-delete")
    }

    func testRealCLIRejectsPlantedEnvironment() throws {
        for assignment in ["process.env.PLANTED='1';", "process.env.__CF_USER_TEXT_ENCODING='malformed';",
                           "process.env.__CF_USER_TEXT_ENCODING='0x0:0x0:0x0';"] {
            try nativeRun(body: Self.refusingCLI.replacingOccurrences(of: "// fixture input", with: assignment),
                          expectsReady: false, witness: "realCLIRejectsPlantedEnvironment", seeded: true,
                          expectedLog: "state_ENV_REPLACED: startup refused")
        }
    }

    func testRelayStopAbortsCorpusLockWait() throws {
        // Two waves exercise the initial admission and a fresh admission after cleanup.
        for _ in 0..<2 {
            try nativeRun(body: approvedCLI(phase: "lock"), expectsReady: true,
                          witness: "relayStopAbortsCorpusLockWait", seeded: true)
        }
    }

    func testRelayStopPreservesPassedLease() throws {
        // Two waves exercise the initial admission and a fresh admission after cleanup.
        for _ in 0..<2 {
            try nativeRun(body: approvedCLI(phase: "write"), expectsReady: true,
                          witness: "relayStopPreservesPassedLease", seeded: true)
        }
    }

    func testRestartRequiresExplicitStaleLockRecovery() throws {
        let killWithLock = Self.realCLIClient.replacingOccurrences(of: "console.log('WITNESS_PASS');", with: """
        const {FilesystemStorage}=await load('src/storage/filesystem.ts');
        const locks=await load('src/sdw/adapters/sdw-memory-backend.ts');
        const storage=new FilesystemStorage(path.join(root,'Library','Application Support','Sanctuary','Fortresses','hermes-memory','state'));
        const dir=storage.namespacePath(locks.MEMORY_BATCH_LOCK_NAMESPACE);
        fs.mkdirSync(dir,{recursive:true,mode:0o700});
        const lock=path.join(dir,locks.sdwMemoryCorpusBatchLockFile());
        fs.writeFileSync(lock,'held',{mode:0o600}); fs.writeFileSync(path.join(root,'lock-path'),lock);
        console.log('WITNESS_PASS'); process.kill(process.pid,'SIGKILL');
        """)
        try nativeRun(body: killWithLock, expectsReady: true, witness: "restartRequiresExplicitStaleLockRecovery",
                      seeded: true, scenario: "restart")
    }

    func testShutdownRepeatedSignalsReapExactChild() throws {
        // Three waves detect a leaked pid/descriptor or an extended deadline after repeated signals.
        for _ in 0..<3 {
            let began = DispatchTime.now().uptimeNanoseconds
            try nativeRun(body: """
            clearTimeout(timer);
            process.on('SIGTERM',()=>{});
            fs.writeFileSync(socketPath+'.pid',String(process.pid));
            console.log('WITNESS_PASS');
            setInterval(()=>process.kill(process.ppid,'SIGTERM'),10);
            """, expectsReady: false, witness: "shutdownRepeatedSignalsReapExactChild")
            let elapsedMS = (DispatchTime.now().uptimeNanoseconds - began) / 1_000_000
            XCTAssertLessThanOrEqual(elapsedMS, 6000, "shutdownRepeatedSignalsReapExactChild")
        }
    }

    func testProductionPeerCompositionRejectsBeforeRead() throws {
        XCTAssertNotEqual(getuid(), RelayProtocolConstants.hermesUID)
        try nativeRun(body: """
        channel.on('data',()=>{throw Error('productionPeerComposition accepted frame');});
        channel.write(frame({type:'ready'}));
        const connect=setInterval(()=>{
          if(!fs.existsSync(socketPath)) return; clearInterval(connect);
          const client=net.createConnection(socketPath);
          client.on('connect',()=>client.write(Buffer.from([255,255,255,255])));
          client.on('error',()=>{});
          client.on('close',()=>{console.log('WITNESS_PASS');process.exit(0);});
        },10);
        """, expectsReady: true, witness: "productionPeerComposition", scenario: "production-peer")
    }

    func testProductionBindReclaimsThroughLockedHelper() throws {
        try nativeRun(body: """
        let bytes=Buffer.alloc(0);
        channel.on('data',chunk=>{
          bytes=Buffer.concat([bytes,chunk]);
          if(bytes.length<4 || bytes.length<4+bytes.readUInt32BE(0))return;
          const message=JSON.parse(bytes.subarray(4,4+bytes.readUInt32BE(0)));
          require('node:assert/strict').equal(message.type,'accepted','lockedReclaimConsumer');
          console.log('WITNESS_PASS');process.exit(0);
        });
        channel.write(frame({type:'ready'}));
        // Two relay poll intervals let bind replace the deliberately pre-existing socket.
        setTimeout(()=>{const client=net.createConnection(socketPath);client.on('error',()=>{});},40);
        """, expectsReady: true, witness: "lockedReclaimConsumer", scenario: "leftover-socket")
    }

    func testProductionSocketPathRejectsUnsafeAncestorsBeforeSpawn() throws {
        for scenario in ["production-socket-owner", "production-socket-group-write"] {
            try nativeRun(body: "process.exit(0);", expectsReady: false,
                          witness: "productionSocketPath", scenario: scenario)
        }
    }

    func testSIGTERMLegIsRequired() throws {
        let began = DispatchTime.now().uptimeNanoseconds
        try nativeRun(body: """
        clearTimeout(timer);
        process.on('SIGTERM',()=>{console.log('WITNESS_PASS SIGTERM');process.exit(0);});
        channel.on('data',()=>{});
        channel.write(frame({type:'ready'}));
        const ready=setInterval(()=>{if(fs.existsSync(socketPath)){clearInterval(ready);process.kill(process.ppid,'SIGTERM');}},10);
        """, expectsReady: true, witness: "sigtermLeg", scenario: "graceful")
        // One second of test scheduling slack includes Node startup; load can exhaust it before SIGTERM.
        let schedulerAllowanceMilliseconds = 1_000
        // The signal step plus that test allowance must finish before the product SIGKILL deadline.
        XCTAssertLessThanOrEqual((DispatchTime.now().uptimeNanoseconds - began) / 1_000_000,
            UInt64(RelayProtocolConstants.probeReplyBoundMilliseconds + schedulerAllowanceMilliseconds), "sigtermLeg deadline")
    }

    func testReapTimeoutPreservesSocket() throws { try unreapedRun("reap-timeout") }
    func testOwnershipLossPreservesSocket() throws { try unreapedRun("ownership-loss") }
    private func unreapedRun(_ scenario: String) throws {
        try nativeRun(body: """
        clearTimeout(timer);
        fs.writeFileSync(socketPath+'.pid',String(process.pid));
        channel.on('data',()=>{console.log('WITNESS_PASS');process.exit(0);});
        channel.write(frame({type:'ready'}));
        const ready=setInterval(()=>{if(fs.existsSync(socketPath)){clearInterval(ready);process.kill(process.ppid,'SIGTERM');}},10);
        """, expectsReady: true, witness: "reapBeforeUnlink", scenario: scenario)
    }

    // Gate-1 schedule: 150 waves of four clients, 60000-byte queries and eight cancels;
    // pause 200 ms every tenth wave. The 20000 ms harness ceiling is four readiness intervals.
    func testChurnWithPausedNodeDeliversShutdown() throws {
        try nativeRun(body: """
        clearTimeout(timer);
        const deadline=setTimeout(()=>{throw Error('churn did not complete');},20000);
        const assert=require('node:assert/strict');
        let bytes=Buffer.alloc(0), waves=0, ending=false, accepted=0;
        channel.on('data',chunk=>{
          bytes=Buffer.concat([bytes,chunk]);
          while(bytes.length>=4 && bytes.length>=4+bytes.readUInt32BE(0)) {
            const n=bytes.readUInt32BE(0),m=JSON.parse(bytes.subarray(4,4+n));bytes=bytes.subarray(4+n);
            if(m.type==='accepted') accepted++;
            if(m.type==='relay_shutdown') {
              assert.ok(ending,'churnShutdown premature stop');
              assert.equal(waves,150,'churnShutdown waves');assert.ok(accepted>4,'churnShutdown admission progress');
              clearTimeout(deadline);console.log('WITNESS_PASS');process.exit(0);
            }
          }
        });
        channel.on('end',()=>{throw Error('churnShutdown unexpected EOF');});
        channel.write(frame({type:'ready'}));
        const big='x'.repeat(60000);
        const wave=()=>{
          if(waves===150){ending=true;process.kill(process.ppid,'SIGTERM');return;}
          waves++;
          if(waves%10===0){channel.pause();setTimeout(()=>channel.resume(),200);}
          let closed=0;
          for(let i=0;i<4;i++){
            const c=net.createConnection(socketPath);c.on('error',()=>{});
            c.on('connect',()=>{const parts=[frame({type:'tools_call',request_id:'r'+i,name:'memory_search',arguments:{query:big}})];
              for(let k=0;k<8;k++)parts.push(frame({type:'cancel',mcp_request_id:'r'+i}));c.end(Buffer.concat(parts));});
            c.on('close',()=>{if(++closed===4)setTimeout(wave,2);});
          }
        };
        const ready=setInterval(()=>{if(fs.existsSync(socketPath)){clearInterval(ready);wave();}},10);
        """, expectsReady: true, witness: "churnShutdown", scenario: "graceful")
    }

    private func nativeRun(body: String, expectsReady: Bool, witness: String, seeded: Bool = false, scenario: String = "", expectedLog: String? = nil) throws {
        var pattern = Array("/tmp/hmr-XXXXXX".utf8CString)
        guard let pointer = mkdtemp(&pattern) else { throw RuntimeFailure.configuration }
        let root = String(cString: pointer)
        defer { try? FileManager.default.removeItem(atPath: root) }
        let node = try XCTUnwrap(["/usr/local/bin/node", "/opt/homebrew/bin/node", "/usr/bin/node"].first {
            FileManager.default.isExecutableFile(atPath: $0)
        })
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        var fingerprint = String(repeating: "a", count: 64)
        if seeded {
            let seed = root + "/seed.cjs"
            var seedBytes = Self.seedScript
            if scenario == "custody" {
                seedBytes = seedBytes.replacingOccurrences(of: "await (await load('src/wrap/passphrase.ts')).persistUserProvidedPassphrase(passphrase,{home:root,storagePath:fortress,platformOverride:'freebsd'});", with: "// Fixture intentionally has no stored boot credential.")
            }
            if scenario == "trap" {
                seedBytes = seedBytes.replacingOccurrences(of: "} finally { await custody", with: "await storage.write('_honeypot_traps','trap.fixture',Buffer.from('{}')); } finally { await custody")
            }
            if scenario == "lock" {
                seedBytes = seedBytes.replacingOccurrences(of: "clearTimeout(timer);", with: "const locks=await load('src/sdw/adapters/sdw-memory-backend.ts'); const dir=storage.namespacePath(locks.MEMORY_BATCH_LOCK_NAMESPACE); fs.mkdirSync(dir,{recursive:true,mode:0o700}); const lock=path.join(dir,locks.sdwMemoryCorpusBatchLockFile()); fs.writeFileSync(lock,'held',{mode:0o600}); fs.writeFileSync(path.join(root,'lock-path'),lock); clearTimeout(timer);")
            }
            try (bootstrap(repository) + seedBytes).write(toFile: seed, atomically: false, encoding: .utf8)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: node)
            process.arguments = [seed]
            process.environment = ["HOME": root, "TMPDIR": "/tmp", "LANG": "C"]
            let log = root + "/seed.log"
            FileManager.default.createFile(atPath: log, contents: nil)
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: log))
            process.standardOutput = handle; process.standardError = handle
            try process.run(); process.waitUntilExit(); try handle.close()
            let seedOutput = try String(contentsOfFile: log, encoding: .utf8)
            XCTAssertEqual(process.terminationStatus, 0, seedOutput)
            fingerprint = try String(contentsOfFile: root + "/pin", encoding: .utf8)
            if scenario == "identity" { fingerprint = String(repeating: "b", count: 64) }
        }
        let script = root + "/child.cjs"
        let socketPath = root + "/memory.sock"
        // Deliberately not CLOEXEC: the native spawn's default must exclude this unrelated descriptor.
        let rawSentinel = open(socketPath + ".sentinel", O_CREAT | O_RDWR, 0o600)
        guard rawSentinel >= 0 else { throw RuntimeFailure.configuration }
        // 0...2 are stdio and 3 is the protocol endpoint; the unrelated witness must be at least fd 4.
        let firstNonProtocolFD = STDERR_FILENO + 2
        let sentinel = fcntl(rawSentinel, F_DUPFD, firstNonProtocolFD)
        close(rawSentinel)
        guard sentinel >= firstNonProtocolFD else { throw RuntimeFailure.configuration }
        defer { close(sentinel) }
        XCTAssertEqual(fcntl(sentinel, F_GETFD) & FD_CLOEXEC, 0, "spawnDescriptorIdentityIsExact fixture")
        let prelude = """
        const fs = require('node:fs');
        const net = require('node:net');
        const socketPath = \(quoted(socketPath));
        const channel = new net.Socket({fd:3});
        channel.on('error', () => process.exit(1));
        const frame = value => { const b=Buffer.from(JSON.stringify(value)); const h=Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h,b]); };
        const timer = setTimeout(()=>{ console.error('fixture deadline'); process.exit(1); }, 4000);
        \(body)
        """
        let scriptBytes = seeded ? bootstrap(repository) + body : prelude
        try scriptBytes.write(toFile: script, atomically: false, encoding: .utf8)
        let fields: [String: Any] = [
            "schema_version": 1, "node_executable": node, "node_entry": script,
            "bridge_log": root + "/bridge.log", "relay_log": root + "/relay.log",
            "public_socket": socketPath, "private_dir": root, "owner_uid": 501,
            "hermes_account": "fixture", "hermes_uid": 502, "group": "fixture",
            "fortress_id": "hermes-memory", "agent_id": "hermes", "identity_fingerprint": fingerprint
        ]
        let config = try RuntimeConfiguration.parse(JSONSerialization.data(withJSONObject: fields))
        if !scenario.isEmpty { try Data().write(to: URL(fileURLWithPath: root + "/" + scenario)) }
        if scenario == "leftover-socket" {
            let stale = socket(AF_UNIX, SOCK_STREAM, 0)
            guard stale >= 0 else { throw RuntimeFailure.socket }
            defer { close(stale) }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(socketPath.utf8) + [0]) }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(stale, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
            }
            XCTAssertEqual(result, 0, "lockedReclaimConsumer fixture")
        }
        let code: Int32
        var fixtureRuntimeToReap: RelayRuntime?
        var fixtureChildReaped = false
        defer {
            if !fixtureChildReaped, let pid = fixtureRuntimeToReap?.child {
                _ = kill(pid, SIGKILL)
                var status: Int32 = 0
                _ = waitpid(pid, &status, 0)
            }
        }
        if seeded || scenario == "production-peer" {
            try JSONSerialization.data(withJSONObject: fields).write(to: URL(fileURLWithPath: root + "/relay-config.json"))
            code = try runEntrypoint(root: root)
        } else {
            let runtime = fixtureRuntime(config, root: root)
            if scenario == "reap-timeout" || scenario == "ownership-loss" { fixtureRuntimeToReap = runtime }
            code = runtime.run()
            if scenario.hasPrefix("production-socket-") {
                XCTAssertEqual(code, EX_CONFIG, "productionSocketPath refusal")
                XCTAssertNil(runtime.child, "productionSocketPath no child spawned")
                XCTAssertFalse(FileManager.default.fileExists(atPath: config.bridgeLog), "productionSocketPath no child log")
                XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath), "productionSocketPath no socket")
                return
            }
            XCTAssertLessThanOrEqual(runtime.peakPrivateQueueFrames, RuntimeLimits.privateQueueFrames, "churnShutdown queue cap")
            XCTAssertLessThanOrEqual(runtime.peakPrivateQueueBytes, RuntimeLimits.privateQueueBytes, "churnShutdown byte cap")
        }
        if scenario == "production-peer" {
            XCTAssertEqual(try? String(contentsOfFile: root + "/peer-refused", encoding: .utf8), "4", "productionPeerComposition zero bytes read")
        }
        if scenario == "reap-timeout" || scenario == "ownership-loss" {
            XCTAssertTrue(FileManager.default.fileExists(atPath: socketPath), "reapBeforeUnlink")
            let log = try String(contentsOfFile: config.relayLog, encoding: .utf8)
            XCTAssertTrue(log.contains(scenario == "reap-timeout" ? "reap_timeout" : "child_ownership_lost"), "reapBeforeUnlink cause")
            XCTAssertTrue(log.contains("leftover_socket=" + socketPath), "reapBeforeUnlink diagnostic")
            let pid = try XCTUnwrap(Int32(String(contentsOfFile: socketPath + ".pid", encoding: .utf8)))
            var status: Int32 = 0
            _ = kill(pid, SIGKILL)
            let result = waitpid(pid, &status, 0)
            fixtureChildReaped = result == pid || (result < 0 && errno == ECHILD)
            XCTAssertEqual(result, pid, "reapBeforeUnlink fixture cleanup")
        }
        XCTAssertEqual(code, scenario == "graceful" ? EX_OK : seeded && expectedLog == nil && scenario != "restart" ? EX_OK : (expectsReady ? EX_SOFTWARE : EX_CONFIG), witness)
        if scenario != "reap-timeout" && scenario != "ownership-loss" {
            XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath), "supervisionConvergesBothDirections")
        }
        let output = try String(contentsOfFile: root + "/bridge.log", encoding: .utf8)
        if let expectedLog {
            XCTAssertTrue(output.contains(expectedLog), "\(witness): \(output)")
            let relayLog = try String(contentsOfFile: root + "/relay.log", encoding: .utf8)
            XCTAssertFalse(relayLog.contains("state_READY scoped"), witness)
            if scenario == "lock" {
                let lockPath = try String(contentsOfFile: root + "/lock-path", encoding: .utf8)
                XCTAssertEqual(try String(contentsOfFile: lockPath, encoding: .utf8), "held", witness)
                XCTAssertTrue(output.contains(lockPath), "staleCorpusLockRefusesReady exact path")
                XCTAssertTrue(output.contains("stop the relay and all fortress writers"), "staleCorpusLockRefusesReady recovery path")
            }
        } else if witness == "realCLIEnvironmentAdmission" {
            XCTAssertTrue(output.contains("state_FORTRESS_UNLOCKED: startup refused"), "realCLIEnvironmentAdmission: \(output)")
        } else if witness != "malformedReadyLeavesNoSocket" && scenario != "ownership-loss" {
            XCTAssertTrue(output.contains("WITNESS_PASS"), "\(witness): \(output)")
        }
        if scenario == "restart" {
            let lockPath = try String(contentsOfFile: root + "/lock-path", encoding: .utf8)
            let before = try String(contentsOfFile: root + "/bridge.log", encoding: .utf8)
            XCTAssertEqual(try runEntrypoint(root: root), EX_CONFIG, "restartRequiresExplicitStaleLockRecovery")
            XCTAssertEqual(try String(contentsOfFile: lockPath, encoding: .utf8), "held", "restartRequiresExplicitStaleLockRecovery")
            XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath), "restartRequiresExplicitStaleLockRecovery")
            let after = try String(contentsOfFile: root + "/bridge.log", encoding: .utf8)
            XCTAssertTrue(String(after.dropFirst(before.count)).contains("never auto-delete"), "restartRequiresExplicitStaleLockRecovery")
            // Explicit fixture operator recovery, only after both supervised children have exited.
            try FileManager.default.removeItem(atPath: lockPath)
            try (bootstrap(repository) + Self.realCLIClient).write(toFile: script, atomically: false, encoding: .utf8)
            XCTAssertEqual(try runEntrypoint(root: root), EX_OK, "restartRequiresExplicitStaleLockRecovery")
            XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath), "restartRequiresExplicitStaleLockRecovery")
        }
        if let pidText = try? String(contentsOfFile: socketPath + ".pid", encoding: .utf8), let pid = Int32(pidText) {
            XCTAssertEqual(kill(pid, 0), -1, "shutdownRepeatedSignalsReapExactChild")
            XCTAssertEqual(errno, ESRCH, "shutdownRepeatedSignalsReapExactChild")
            var status: Int32 = 0
            XCTAssertEqual(waitpid(pid, &status, WNOHANG), -1, "shutdownRepeatedSignalsReapExactChild")
            XCTAssertEqual(errno, ECHILD, "shutdownRepeatedSignalsReapExactChild")
        }
    }

    private func runEntrypoint(root: String) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["xctest", "-XCTest", "HermesMemoryRelayCoreTests.RuntimeContractTests/testRealChildReadyFollowsComposition", Bundle(for: Self.self).bundlePath]
        var environment = ProcessInfo.processInfo.environment
        environment["HMR_ENTRYPOINT_FIXTURE"] = root
        process.environment = environment
        try process.run(); process.waitUntilExit()
        return process.terminationStatus
    }

    private func fixtureRuntime(_ config: RuntimeConfiguration, root: String) -> RelayRuntime {
        let unsafeOwner = FileManager.default.fileExists(atPath: root + "/production-socket-owner")
        let writableAncestor = FileManager.default.fileExists(atPath: root + "/production-socket-group-write")
        if unsafeOwner || writableAncestor || FileManager.default.fileExists(atPath: root + "/production-peer") {
            return try! RelayRuntime.productionRuntime(config, lookup: RuntimeFixtureAccount(), admin: RuntimeFixtureAdmin(),
                home: root, group: getgid(), fileSystem: FixtureSocketMetadata(root: root, unsafeOwner: unsafeOwner, writableAncestor: writableAncestor), observeRejectedPeer: { fd in
                    var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    _ = poll(&item, 1, Int32(RelayProtocolConstants.probeReplyBoundMilliseconds))
                    // SO_NREAD observes the receive queue length without reading or peeking any client byte.
                    var unread: Int32 = -1, size = socklen_t(MemoryLayout<Int32>.size)
                    XCTAssertEqual(getsockopt(fd, SOL_SOCKET, SO_NREAD, &unread, &size), 0)
                    try! String(unread).write(toFile: root + "/peer-refused", atomically: false, encoding: .utf8)
                })
        }
        return RelayRuntime(configuration: config, environment: ["HOME": root, "LANG": "C", "TMPDIR": "/tmp"],
                     socketGroup: getgid(), instanceLock: DarwinInstanceLock(), verifySocketPath: {
            let info = try RuntimeConfiguration.metadata(root)
            guard info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else { throw RuntimeFailure.configuration }
        }, verifyPeer: { fd in
            if FileManager.default.fileExists(atPath: root + "/reject-peer") {
                var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                _ = poll(&item, 1, Int32(RelayProtocolConstants.probeReplyBoundMilliseconds))
                var prefix = [UInt8](repeating: 0, count: RelayProtocolConstants.frameLengthPrefixBytes)
                XCTAssertEqual(recv(fd, &prefix, prefix.count, MSG_PEEK | MSG_DONTWAIT), prefix.count, "peerAuthenticationPrecedesDecode")
                XCTAssertEqual(prefix, [255, 255, 255, 255], "peerAuthenticationPrecedesDecode")
                // The production canonical verifier refuses this actual non-Hermes uid.
                _ = try DarwinPeerCredentialProvider().peerUid(forFileDescriptor: fd)
                throw RuntimeFailure.socket
            }
            // Fixture peers authenticate their actual kernel uid; production still pins Hermes uid 502.
            _ = try UnixPeerVerifier.requirePeer(socket: fd, expectedUID: getuid())
        }, ordinaryReadsEnabled: { !FileManager.default.fileExists(atPath: root + "/drain-only") }, reapChild: { pid, status, options in
            if FileManager.default.fileExists(atPath: root + "/reap-timeout") { return 0 }
            if FileManager.default.fileExists(atPath: root + "/ownership-loss"), FileManager.default.fileExists(atPath: config.publicSocket) {
                errno = ECHILD; return -1
            }
            return Darwin.waitpid(pid, status, options)
        })
    }

    private func quoted(_ value: String) -> String {
        String(data: try! JSONEncoder().encode(value), encoding: .utf8)!
    }

    private func bootstrap(_ repository: String) -> String {
        """
        const fs = require('node:fs');
        const net = require('node:net');
        const path = require('node:path');
        const root = process.env.HOME;
        const socketPath = path.join(root, 'memory.sock');
        const repository = \(quoted(repository));
        const frame = value => { const b=Buffer.from(JSON.stringify(value)); const h=Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h,b]); };
        const timer = setTimeout(()=>{ console.error('fixture deadline'); process.exit(1); }, 15000);
        const load = async relative => import(require('node:url').pathToFileURL(path.join(repository, 'server', relative)).href);
        const boot = (async()=>{
          const {register} = await load('node_modules/tsx/dist/esm/api/index.mjs'); register();
          (await load('test/setup/keychain-memory-store.ts')).installInMemoryKeychainStore();
        })();

        """
    }

    private static let seedScript = """
    boot.then(async()=>{
      const { FilesystemStorage } = await load('src/storage/filesystem.ts');
      const { establishMaster } = await load('src/core/master-custody.ts');
      const { IdentityManager } = await load('src/cognitive/tools.ts');
      const { createIdentity } = await load('src/core/identity.ts');
      const { derivePurposeKey } = await load('src/core/key-derivation.ts');
      const { fromBase64url } = await load('src/core/encoding.ts');
      const { memoryProvenancePublicKeyFingerprint } = await load('src/sdw/memory-provenance-bad-signers.ts');
      let fortress = path.join(root,'Library','Application Support','Sanctuary','Fortresses','hermes-memory');
      fs.mkdirSync(fortress,{recursive:true,mode:0o700});
      fortress=fs.realpathSync(fortress);
      const storage = new FilesystemStorage(path.join(fortress,'state'));
      const passphrase = 'disposable relay fixture passphrase';
      await (await load('src/wrap/passphrase.ts')).persistUserProvidedPassphrase(passphrase,{home:root,storagePath:fortress,platformOverride:'freebsd'});
      const custody = await establishMaster({storage,passphrase,firstRun:{installMode:'headless',mintRecoveryKey:false}});
      try {
        const identities = new IdentityManager(storage,custody.masterKey); await identities.load();
        const {storedIdentity} = createIdentity('relay-fixture',derivePurposeKey(custody.masterKey,'identity-encryption'),'passphrase');
        await identities.save(storedIdentity);
        fs.writeFileSync(path.join(root,'pin'),memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key)),{mode:0o600});
        const signing = await load('src/sdw/memory-provenance-signing.ts');
        const {fortressIdFromStoragePath} = await load('src/dashboard/v1_1/wiring.ts');
        const adapter = (await load('src/index.ts')).createSdwMemoryAdapter({
          mode:'standard', storage, masterKey:custody.masterKey, fortressId:fortressIdFromStoragePath(fortress),ownerRef:'hermes',
          resolvePrimarySigningHandle:signing.createPrimaryMemoryProvenanceSigningHandleResolver(identities,custody.masterKey),
          resolveSignerPublicKey:signing.createPrimaryMemoryProvenancePublicKeyResolver(identities),
          resolveMemoryIntegrityState:async()=> 'state_PRE_MIGRATION',
        });
        const {memoryInsertIngress} = await load('src/sdw/memory-provenance-ingress.ts');
        await adapter.insertPassage({passage_id:'seed',text:'Cedar lantern fixture text',tags:['fixture'],provenanceContext:memoryInsertIngress(undefined,'user_content')},'user_content');
      } finally { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); }
      clearTimeout(timer);
    }).catch(error=>{console.error(error);process.exit(1);});
    """

    private func approvedCLI(phase: String) -> String {
        let setup = """
        const phase=\(quoted(phase));
        const assert=require('node:assert/strict');
        const {HermesBridgeCore}=await load('src/hermes-memory-bridge/bridge-core.ts');
        let core;
        const onDrained=HermesBridgeCore.prototype.onDrained;
        HermesBridgeCore.prototype.onDrained=function(listener){core=this;return onDrained.call(this,listener);};
        const {FilesystemStorage}=await load('src/storage/filesystem.ts');
        const {MEMORY_BATCH_LOCK_NAMESPACE}=await load('src/sdw/adapters/sdw-memory-backend.ts');
        const {SDW_DOCUMENT_CORPUS_NAMESPACE}=await load('src/sdw/records.ts');
        const withLock=FilesystemStorage.prototype.withNamespaceLock;
        const storageWrite=FilesystemStorage.prototype.write;
        let armed=false, writes=0;
        FilesystemStorage.prototype.withNamespaceLock=async function(namespace,name,operation,options={}) {
          if(armed && phase==='lock' && namespace===MEMORY_BATCH_LOCK_NAMESPACE) {
            process.kill(process.ppid,'SIGTERM');
            await new Promise((resolve,reject)=>{
              options.abortSignal.addEventListener('abort',()=>{
                this.list(SDW_DOCUMENT_CORPUS_NAMESPACE,'doc.mem.hermes.').then(docs=>{
                  assert.equal(docs.length,1,'relayStopAbortsCorpusLockWait');
                  console.log('WITNESS_PASS');reject(Error('fixture lock wait aborted'));
                }).catch(reject);
              },{once:true});
            });
          }
          return withLock.call(this,namespace,name,operation,options);
        };
        FilesystemStorage.prototype.write=async function(namespace,key,data) {
          if(armed && phase==='write' && namespace===SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith('doc.mem.hermes.')) {
            writes++;
            process.kill(process.ppid,'SIGTERM');
            // 100 ms is one quarter of the 400 ms stop tail; the actual CLI must retain its passed lease.
            await new Promise(resolve=>setTimeout(resolve,100));
            await storageWrite.call(this,namespace,key,data);
            assert.equal(writes,1,'relayStopPreservesPassedLease');
            assert.equal((await this.list(namespace,'doc.mem.hermes.')).length,2,'relayStopPreservesPassedLease');
            console.log('WITNESS_PASS'); return;
          }
          return storageWrite.call(this,namespace,key,data);
        };
        """
        var body = Self.realCLIClient.replacingOccurrences(of: "if(fs.existsSync(socketPath))", with: setup + "\nif(fs.existsSync(socketPath))")
        // The approval capability is captured only in this test process, never exposed by the product shell.
        body = body.replacingOccurrences(of: "const before=fs.readdirSync(corpus).sort();", with: "const before=fs.readdirSync(corpus).sort(); armed=true;")
        let cancellation = "client.write(frame({type:'cancel',mcp_request_id:'insert'}));"
        body = body.replacingOccurrences(of: cancellation, with: "const entry=core.snapshot().ledger.entry; core.ownerApprove(entry.id,entry.textSha256); await new Promise(()=>{});")
        // exercise is outside the boot closure, so the test-only capture lives in its enclosing script scope.
        body = "let core, armed=false;\n" + body.replacingOccurrences(of: "        let core;", with: "")
            .replacingOccurrences(of: "let core;", with: "")
            .replacingOccurrences(of: "let armed=false, writes=0;", with: "let writes=0;")
        return body
    }

    private static let refusingCLI = """
    boot.then(async()=>{
      // fixture input
      process.argv=[process.execPath,path.join(repository,'server/src/cli.ts'),'hermes-memory-bridge','run','--relay-fd','3'];
      await load('src/cli.ts');
    }).catch(error=>{console.error(error);process.exit(1);});
    """

    private static let realCLIClient = """
    boot.then(async()=>{
      if(fs.existsSync(socketPath)) throw Error('publicSocketWaitsForRealChildReady: early bind');
      const CoreForObservation=(await load('src/hermes-memory-bridge/bridge-core.ts')).HermesBridgeCore;
      let compositionAttached=false;
      const originalOnDrained=CoreForObservation.prototype.onDrained;
      CoreForObservation.prototype.onDrained=function(listener){compositionAttached=true;return originalOnDrained.call(this,listener);};
      const originalWrite = net.Socket.prototype.write;
      let readyCount=0;
      net.Socket.prototype.write = function(chunk,...args) {
        if(this._handle?.fd===3 && Buffer.isBuffer(chunk) && chunk.length>=4) {
          try {
            const message=JSON.parse(chunk.subarray(4).toString());
            if(message.type==='ready') {
              if(!compositionAttached) throw Error('realChildReadyFollowsComposition: ready before attachment');
              readyCount++;
              if(readyCount!==1 || fs.existsSync(socketPath)) throw Error('publicSocketWaitsForRealChildReady: premature socket');
              setImmediate(()=>exercise().catch(error=>{console.error(error);process.exit(1);}));
            }
          } catch(error) { if(String(error).includes('publicSocketWaits') || String(error).includes('realChildReadyFollowsComposition')) throw error; }
        }
        return originalWrite.call(this,chunk,...args);
      };
      process.argv=[process.execPath,path.join(repository,'server/src/cli.ts'),'hermes-memory-bridge','run','--relay-fd','3'];
      await load('src/cli.ts');
    }).catch(error=>{console.error(error);process.exit(1);});
    async function exercise() {
      const assert = require('node:assert/strict');
      while(!fs.existsSync(socketPath)) await new Promise(resolve=>setTimeout(resolve,10));
      const client=net.createConnection(socketPath);
      let bytes=Buffer.alloc(0), queue=[], waiters=[];
      client.on('data',chunk=>{
        bytes=Buffer.concat([bytes,chunk]);
        while(bytes.length>=4 && bytes.length>=4+bytes.readUInt32BE(0)) {
          const n=bytes.readUInt32BE(0), value=JSON.parse(bytes.subarray(4,4+n)); bytes=bytes.subarray(4+n);
          const waiter=waiters.shift(); if(waiter) waiter(value); else queue.push(value);
        }
      });
      await new Promise((resolve,reject)=>{client.once('connect',resolve);client.once('error',reject);});
      const next=()=>queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve=>waiters.push(resolve));
      const call=async(value)=>{client.write(frame(value));return await next();};
      assert.equal((await call({type:'hello',request_id:'hello',protocol_version:'2026-10-12',client_name:'fixture'})).type,'result','hello');
      const catalog=await call({type:'tools_list',request_id:'catalog'});
      assert.deepEqual(catalog.payload.tools.map(t=>t.name).sort(),['memory_get','memory_insert','memory_search'],'realRelayCatalogIsExact');
      const get=await call({type:'tools_call',request_id:'get',name:'memory_get',arguments:{passage_id:'seed'}});
      assert.equal(get.type,'result','byte-equal get: '+JSON.stringify(get));
      const payload=JSON.parse(get.payload.content[0].text);
      assert.equal(payload.passage.text,'Cedar lantern fixture text','byte-equal get');
      const search=await call({type:'tools_call',request_id:'search',name:'memory_search',arguments:{query:'Cedar'}});
      assert.equal(JSON.parse(search.payload.content[0].text).results[0].passage.passage_id,'seed','seeded scoped search');
      const hidden=await call({type:'tools_call',request_id:'hidden',name:'state_export',arguments:{}});
      assert.deepEqual(hidden,{type:'error',request_id:'hidden',message:'Memory request denied.'},'realRelayProjectsFixedDenials');
      const later=await call({type:'tools_call',request_id:'later',name:'memory_get',arguments:{passage_id:'seed'}});
      assert.equal(JSON.parse(later.payload.content[0].text).passage.text,'Cedar lantern fixture text','realRelayProjectsFixedDenials later read');
      const tcp=require('node:child_process').spawnSync('/usr/sbin/lsof',['-a','-p',String(process.ppid),'-iTCP','-sTCP:LISTEN','-Fn'],{encoding:'utf8',timeout:2000});
      assert.equal(tcp.status,1,'runtimeHasNoTcpListeners relay');
      assert.equal(tcp.stdout.trim(),'','runtimeHasNoTcpListeners relay');
      const servers=process._getActiveHandles().filter(handle=>handle instanceof net.Server).map(handle=>handle.address());
      assert.equal(servers.some(address=>address && typeof address==='object'),false,'runtimeHasNoTcpListeners');
      assert.equal(servers.some(address=>typeof address==='string' && !address.includes('.reader-')),false,'runtimeUsesOnlyDocumentedPrivateHandles');
      assert.equal(fs.existsSync(path.join(root,'relay.sock')),false,'runtimeUsesOnlyDocumentedPrivateHandles');
      const corpus=path.join(root,'Library','Application Support','Sanctuary','Fortresses','hermes-memory','state','_sdw_document_corpus');
      const before=fs.readdirSync(corpus).sort();
      client.write(frame({type:'tools_call',request_id:'insert',name:'memory_insert',arguments:{text:'Unapproved fixture text',taint:'user_content',passage_id:'unapproved'}}));
      const log=path.join(root,'bridge.log');
      while(!fs.readFileSync(log,'utf8').includes('owner approval is deferred')) await new Promise(resolve=>setTimeout(resolve,10));
      assert.equal(queue.length,0,'production insert remains pending');
      client.write(frame({type:'cancel',mcp_request_id:'insert'}));
      await next();
      assert.deepEqual(fs.readdirSync(corpus).sort(),before,'cancel writes zero documents');
      client.destroy();
      console.log('WITNESS_PASS');
      clearTimeout(timer);
      process.kill(process.ppid,'SIGTERM');
    }
    """

    private static let probeChild = """
    const assert=require('node:assert/strict');
    let bytes=Buffer.alloc(0), client, sawCancel=false;
    channel.on('data',chunk=>{
      bytes=Buffer.concat([bytes,chunk]);
      while(bytes.length>=4 && bytes.length>=4+bytes.readUInt32BE(0)) {
        const n=bytes.readUInt32BE(0), message=JSON.parse(bytes.subarray(4,4+n)); bytes=bytes.subarray(4+n);
        if(message.type==='frame') {
          const request=JSON.parse(Buffer.from(message.frame_b64,'base64'));
          if(request.type==='tools_list') {
            // Test composition suspends ordinary reads; only the real fd probe drain can consume this cancel.
            fs.writeFileSync(require('node:path').join(process.env.HOME,'drain-only'),'');
            client.write(frame({type:'cancel',mcp_request_id:'pending'}),()=>{
              channel.write(frame({type:'probe',connection_id:message.connection_id,nonce:'a'.repeat(32)}));
            });
          } else if(request.type==='cancel') sawCancel=true;
        }
        if(message.type==='probe_reply') {
          assert.equal(sawCancel,true,'probeDrainSeesCancelBeforeReply');
          console.log('WITNESS_PASS'); client.destroy(); process.exit(0);
        }
      }
    });
    channel.write(frame({type:'ready'}));
    const connect=setInterval(()=>{
      if(!fs.existsSync(socketPath)) return;
      clearInterval(connect);
      client=net.createConnection(socketPath);
      client.on('error',error=>{throw error;});
      client.on('connect',()=>client.write(frame({type:'tools_list',request_id:'pending'})));
    },10);
    """

    private static let transportChild = """
    let privateBytes=Buffer.alloc(0), publicBytes=Buffer.alloc(0), accepted=false, calls=0;
    channel.on('data',chunk=>{
      privateBytes=Buffer.concat([privateBytes,chunk]);
      while(privateBytes.length>=4 && privateBytes.length>=4+privateBytes.readUInt32BE(0)) {
        const n=privateBytes.readUInt32BE(0), message=JSON.parse(privateBytes.subarray(4,4+n)); privateBytes=privateBytes.subarray(4+n);
        if(message.type==='accepted') { if(accepted) throw Error('duplicate accepted'); accepted=true; }
        if(message.type==='frame') {
          if(!accepted) throw Error('frame before accepted');
          const request=JSON.parse(Buffer.from(message.frame_b64,'base64')); calls++;
          const result=Buffer.from(JSON.stringify({type:'result',request_id:request.request_id,payload:{ok:true}}));
          channel.write(frame({type:'response',connection_id:message.connection_id,request_id:request.request_id,result_b64:result.toString('base64')}));
        }
        if(message.type==='relay_shutdown') process.exit(0);
      }
    });
    if(fs.existsSync(socketPath)) throw Error('bind before ready');
    channel.write(frame({type:'ready'}));
    const connect=setInterval(()=>{
      if(!fs.existsSync(socketPath)) return;
      clearInterval(connect);
      const client=net.createConnection(socketPath);
      client.on('error', error=>{ throw error; });
      client.on('connect',()=>{
        client.write(frame({type:'hello',request_id:'hello',protocol_version:'1',client_name:'fixture'}));
        // One second is half the protocol probe bound; assert actual decode progress before the fixture watchdog.
        setTimeout(()=>require('node:assert/strict').equal(calls,2,'runtimeProcessesMultipleBoundedFrames'),1000);
      });
      client.on('data',chunk=>{
        publicBytes=Buffer.concat([publicBytes,chunk]);
        while(publicBytes.length>=4 && publicBytes.length>=4+publicBytes.readUInt32BE(0)) {
          const n=publicBytes.readUInt32BE(0), result=JSON.parse(publicBytes.subarray(4,4+n)); publicBytes=publicBytes.subarray(4+n);
          if(result.type==='pong') continue;
          if(result.request_id==='hello') client.write(Buffer.concat([frame({type:'ping'}),frame({type:'tools_list',request_id:'list'})]));
          else if(result.request_id==='list') {
            if(calls!==2) throw Error('frame count');
            console.log('WITNESS_PASS'); client.destroy(); channel.destroy(); clearTimeout(timer); process.exit(0);
          } else throw Error('unexpected response');
        }
      });
    }, 10);
    """
}

// Socket metadata is the only filesystem port here; the peer check inspects the real connected descriptor.
private struct FixtureSocketMetadata: RelayFileSystem {
    let root: String
    var unsafeOwner = false
    var writableAncestor = false
    func lstat(_ path: String) throws -> PathMetadata {
        if path == "/tmp" {
            // Hermes uid is neither root nor the owner pin; 0775 adds group write to a valid ancestor.
            return PathMetadata(owner: unsafeOwner ? RelayProtocolConstants.hermesUID : 0, group: getgid(),
                mode: writableAncestor ? 0o775 : 0o755, isDirectory: true, isSymlink: false)
        }
        return PathMetadata(owner: path == root ? getuid() : 0, group: getgid(),
            mode: path == root ? RelayProtocolConstants.socketDirectoryMode : 0o755,
            isDirectory: true, isSymlink: false)
    }
    func unlink(_ path: String) throws { throw RuntimeFailure.socket }
    func chmod(_ path: String, _ mode: mode_t) throws { throw RuntimeFailure.socket }
}
