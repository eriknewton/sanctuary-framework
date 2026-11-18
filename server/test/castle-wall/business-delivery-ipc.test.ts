// W-TS-CONSUMER
import {it,expect} from "vitest";
import {startLinuxAuditDrainLoop} from "../../src/castle-wall/runtime/linux-audit-drain.js";
import type {IpcClient} from "../../src/castle-wall/runtime/ipc-client.js";
import type {AuditConsumer} from "../../src/castle-wall/runtime/audit-consumer.js";
it("requires Business dependencies before the live loop can select a fallback",async()=>{
  const handles:ReturnType<typeof startLinuxAuditDrainLoop>[]=[];
  try {
    for(const mode of [{kind:"Business"},{kind:"Business",pin:{},committed_state:{}}]) {
      expect(()=>{handles.push(startLinuxAuditDrainLoop({} as IpcClient,{} as AuditConsumer,{
        mode:mode as never,setTimer:()=>0,clearTimer:()=>{},onDrainFault:()=>{},
      }));},"missing Business dependencies refuse at the loop boundary").toThrow("BUSINESS_DEPENDENCIES");
    }
  } finally {for(const handle of handles) await handle.stop();}
});

import {IpcClient as Client,type IpcTransport} from "../../src/castle-wall/runtime/ipc-client.js";
import {frame,parseFrame} from "../../src/castle-wall/ipc/framing.js";
import {encrypt} from "../../src/core/encryption.js";
import {CAP_BUSINESS_DELIVERY} from "../../src/castle-wall/ipc/messages.js";
import type {BusinessDeliveryAck} from "../../src/signing/business-append-contract.js";
const ack:BusinessDeliveryAck={version:1,identity:{version:1,sequence:1,commitment:"sha256:"+"1".repeat(64),envelope_sha256:"sha256:"+"2".repeat(64)}};
async function ipc(capabilities=[CAP_BUSINESS_DELIVERY]) {
  let receive!:(bytes:Uint8Array)=>void;
  let reply:(params:Record<string,unknown>)=>unknown=params=>({...params,type:"business_delivery_ack_response",ok:true});
  const sent:Record<string,unknown>[]=[];
  const transport:IpcTransport={onData:cb=>{receive=cb;return ()=>{};},close:async()=>{},send:async bytes=>{
    const parsed=parseFrame(bytes);if(parsed.kind!=="complete")throw Error("frame");
    const params=JSON.parse(parsed.body).params as Record<string,unknown>;sent.push(params);
    if(params.type==="business_delivery_ack") queueMicrotask(()=>receive(frame(JSON.stringify({jsonrpc:"2.0",method:"sanctuary.castle_wall.business_delivery_ack_response",params:reply(params)}))));
  }};
  const encryptionKey=new Uint8Array(32).fill(9);
  const client=Client.createBusiness(transport,{fortressId:"deadbeef",signingKeyId:"test",encryptedPrivateKey:encrypt(new Uint8Array(32).fill(7),encryptionKey),encryptionKey});
  const ready=client.start();
  receive(frame(JSON.stringify({jsonrpc:"2.0",method:"sanctuary.castle_wall.handshake_challenge",params:{type:"handshake_challenge",nonce_b64url:Buffer.alloc(32,1).toString("base64url"),protocol_version:2,capabilities}})));
  await ready;
  return {client,sent,reply:(fn:typeof reply)=>{reply=fn;},receive};
}
it("binds Business capability into the client handshake and correlates exact ACK",async()=>{
  const p=await ipc();try {expect(p.sent[0].capabilities).toContain(CAP_BUSINESS_DELIVERY);await p.client.sendBusinessAck(ack);expect(p.sent[1].type).toBe("business_delivery_ack");}finally{await p.client.close();}
});
it("capability downgrade never falls back to Legacy ACK",async()=>{
  const p=await ipc([]);try {await expect(p.client.businessDrainRequest()).rejects.toThrow("BUSINESS_CAPABILITY");await expect(p.client.sendBusinessAck(ack)).rejects.toThrow("BUSINESS_ACK");expect(p.sent).toHaveLength(1);}finally{await p.client.close();}
});
it("rejects changed identity and refused acknowledgement responses",async()=>{
  const p=await ipc();try {
    for(const field of ["sequence","commitment","envelope_sha256"]){
      p.reply(params=>({type:"business_delivery_ack_response",request_id:params.request_id,ack:{...ack,identity:{...ack.identity,[field]:field==="sequence"?2:"sha256:"+"3".repeat(64)}},ok:true}));
      await expect(p.client.sendBusinessAck(ack)).rejects.toThrow("BUSINESS_ACK");
    }
    p.reply(params=>({type:"business_delivery_ack_response",request_id:params.request_id,ack,ok:false}));
    await expect(p.client.sendBusinessAck(ack)).rejects.toThrow("BUSINESS_ACK");
  }finally{await p.client.close();}
});
it("strict Business response parsing rejects duplicate keys before object use",async()=>{
  const p=await ipc();try {
    const request=p.client.businessDrainRequest();
    const id=p.sent.at(-1)!.request_id;
    p.receive(frame('{"jsonrpc":"2.0","method":"business_drain_response","params":{"type":"business_drain_response","request_id":'+JSON.stringify(id)+',"event":null,"event":null,"error":null}}'));
    await expect(request).rejects.toThrow("malformed JSON");
  }finally{await p.client.close();}
});
