import Darwin
import Foundation
import XCTest
import MemoryGrantPeer
@testable import HermesMemoryRelayCore

final class RuntimeContractTests: XCTestCase {
    func testRuntimeProcessesMultipleBoundedFrames() throws {
        try nativeRun(body: Self.transportChild, expectsReady: true, witness: "runtimeProcessesMultipleBoundedFrames")
    }

    func testPublicSocketWaitsForRealChildReady() throws {
        try nativeRun(body: "if (fs.existsSync(socketPath)) throw Error('early bind'); console.log('WITNESS_PASS'); process.exit(0);",
                      expectsReady: false, witness: "publicSocketWaitsForRealChildReady")
    }

    func testMalformedReadyLeavesNoSocket() throws {
        try nativeRun(body: "channel.write(frame({type:'pong'})); setTimeout(()=>{ console.log('WITNESS_PASS'); process.exit(0); }, 20);",
                      expectsReady: false, witness: "malformedReadyLeavesNoSocket")
    }

    func testSpawnDescriptorIdentityIsExact() throws {
        try nativeRun(body: "if (!fs.fstatSync(3).isSocket()) throw Error('fd 3 is not a socket'); console.log('WITNESS_PASS'); process.exit(0);",
                      expectsReady: false, witness: "spawnDescriptorIdentityIsExact")
    }

    func testSpawnUsesOnlyConfiguredEnvironment() throws {
        try nativeRun(body: """
        if (Object.keys(process.env).sort().join(',') !== 'HERMES_MEMORY_AGENT_ID,HERMES_MEMORY_BRIDGE_IDENTITY,HERMES_MEMORY_FORTRESS_ID,HOME,LANG,TMPDIR') throw Error('environment differs: '+Object.keys(process.env).sort().join(','));
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

    private func nativeRun(body: String, expectsReady: Bool, witness: String) throws {
        var pattern = Array("/tmp/hmr-XXXXXX".utf8CString)
        guard let pointer = mkdtemp(&pattern) else { throw RuntimeFailure.configuration }
        let root = String(cString: pointer)
        defer { try? FileManager.default.removeItem(atPath: root) }
        let node = try XCTUnwrap(["/usr/local/bin/node", "/opt/homebrew/bin/node", "/usr/bin/node"].first {
            FileManager.default.isExecutableFile(atPath: $0)
        })
        let script = root + "/child.cjs"
        let socketPath = root + "/memory.sock"
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
        try prelude.write(toFile: script, atomically: false, encoding: .utf8)
        let fields: [String: Any] = [
            "schema_version": 1, "node_executable": node, "node_entry": script,
            "bridge_log": root + "/bridge.log", "relay_log": root + "/relay.log",
            "public_socket": socketPath, "private_dir": root, "owner_uid": 501,
            "hermes_account": "fixture", "hermes_uid": 502, "group": "fixture",
            "fortress_id": "hermes-memory", "agent_id": "hermes", "identity_fingerprint": String(repeating: "a", count: 64)
        ]
        let config = try RuntimeConfiguration.parse(JSONSerialization.data(withJSONObject: fields))
        let runtime = RelayRuntime(configuration: config, environment: ["HOME": root, "LANG": "C", "TMPDIR": root],
                                   socketGroup: getgid(), instanceLock: DarwinInstanceLock(), verifySocketPath: {
            let info = try RuntimeConfiguration.metadata(root)
            XCTAssertEqual(info.st_uid, getuid())
        }, verifyPeer: { fd in
            // Test composition authenticates this process's temporary peer; installed admission remains UID 502.
            _ = try UnixPeerVerifier.requirePeer(socket: fd, expectedUID: getuid())
        })
        let code = runtime.run()
        XCTAssertEqual(code, expectsReady ? EX_SOFTWARE : EX_CONFIG, witness)
        XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath), "supervisionConvergesBothDirections")
        let output = try String(contentsOfFile: root + "/bridge.log", encoding: .utf8)
        if witness == "realCLIEnvironmentAdmission" {
            XCTAssertTrue(output.contains("state_ENV_REPLACED: startup refused"), "realCLIEnvironmentAdmission: \(output)")
        } else if witness != "malformedReadyLeavesNoSocket" {
            XCTAssertTrue(output.contains("WITNESS_PASS"), "\(witness): \(output)")
        }
    }

    private func quoted(_ value: String) -> String {
        String(data: try! JSONEncoder().encode(value), encoding: .utf8)!
    }

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
      client.on('connect',()=>client.write(frame({type:'hello',request_id:'hello',protocol_version:'1',client_name:'fixture'})));
      client.on('data',chunk=>{
        publicBytes=Buffer.concat([publicBytes,chunk]);
        while(publicBytes.length>=4 && publicBytes.length>=4+publicBytes.readUInt32BE(0)) {
          const n=publicBytes.readUInt32BE(0), result=JSON.parse(publicBytes.subarray(4,4+n)); publicBytes=publicBytes.subarray(4+n);
          if(result.request_id==='hello') client.write(frame({type:'tools_list',request_id:'list'}));
          else if(result.request_id==='list') {
            if(calls!==2) throw Error('frame count');
            console.log('WITNESS_PASS'); client.destroy(); channel.destroy(); clearTimeout(timer); process.exit(0);
          } else throw Error('unexpected response');
        }
      });
    }, 10);
    """
}
