import {it,expect} from "vitest";
import {publicFrame,parsePublicFrame,RESPONSE_MAX_BYTES} from "../../src/signing/service.js";
it("public response cap precedes allocation",()=>{expect(()=>publicFrame({op:"x".repeat(RESPONSE_MAX_BYTES)})).toThrow("K1_REFUSED");expect(parsePublicFrame(publicFrame({op:"READY"}))).toEqual({op:"READY"});});
it("truncated, duplicate and noncanonical public responses refuse",()=>{
  for(const body of ['{"op":"READY","op":"READY"}','{ "op":"READY"}']){const b=Buffer.from(body),size=Buffer.alloc(4);size.writeUInt32BE(b.length);expect(()=>parsePublicFrame(Buffer.concat([size,b]))).toThrow();}
  expect(()=>parsePublicFrame(publicFrame({op:"READY"}).subarray(1))).toThrow();
});
