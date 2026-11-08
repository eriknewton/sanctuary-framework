import {it,expect} from "vitest";
import {readFileSync,readdirSync} from "node:fs";
import {createHash} from "node:crypto";
import {resolve,dirname} from "node:path";
import ts from "typescript";
import {INERT_SIGNABLE_ADAPTERS} from "../../src/signing/service.js";
const sourceRoot=resolve("src");
const expectedImports={
  "signing/service.ts": [
    "../core/identity.js",
    "../linux-business/producer-custody.js",
    "../smb/parse-strict.js",
    "./contract.js",
    "./identity-provider.js",
    "./record-signer.js",
    "./strict-verifier.js",
    "node:child_process",
    "node:crypto",
    "node:crypto",
    "node:fs"
  ],
  "signing/record-signer.ts": [
    "../core/signing-domains.js",
    "./contract.js",
    "./strict-verifier.js",
    "zod"
  ],
  "signing/contract.ts": [
    "../smb/jcs.js",
    "../smb/parse-strict.js",
    "./linux-business-records.js",
    "node:crypto",
    "zod"
  ],
  "signing/custody-transaction.ts": [
    "../linux-business/activation-anchor.js",
    "../smb/parse-strict.js",
    "./contract.js",
    "./durable-store.js",
    "zod"
  ],
  "signing/durable-store.ts": [
    "./contract.js"
  ],
  "signing/lifecycle.ts": [
    "./contract.js",
    "./protocol-transitions.json"
  ],
  "linux-business/activation-anchor.ts": [
    "../signing/contract.js",
    "../smb/parse-strict.js",
    "node:crypto",
    "zod"
  ],
  "signing/worker.ts": [
    "../core/encryption.js",
    "../core/identity.js",
    "../core/key-derivation.js",
    "../core/master-custody.js",
    "../linux-business/producer-custody.js",
    "../smb/parse-strict.js",
    "../storage/interface.js",
    "./binding-store.js",
    "./contract.js",
    "./provision.js",
    "./record-signer.js",
    "./service.js",
    "node:fs",
    "node:tty"
  ],
  "signing/strict-verifier.ts": [
    "../core/identity.js",
    "./contract.js",
    "zod"
  ]
};
function ast(name:string){return ts.createSourceFile(name,readFileSync(resolve(sourceRoot,name),"utf8"),ts.ScriptTarget.Latest,true);}
function imports(name:string){return ast(name).statements.filter(ts.isImportDeclaration).map(n=>(n.moduleSpecifier as ts.StringLiteral).text).sort();}
function dependencies(name:string){
  const result:string[]=[];
  function visit(node:ts.Node){
    if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier&&ts.isStringLiteral(node.moduleSpecifier))result.push(node.moduleSpecifier.text);
    if(ts.isCallExpression(node)&&(node.expression.kind===ts.SyntaxKind.ImportKeyword||node.expression.getText()==="require")){
      if(node.arguments.length===1&&ts.isStringLiteral(node.arguments[0]))result.push(node.arguments[0].text);
    }
    ts.forEachChild(node,visit);
  }
  visit(ast(name));return result;
}
it("pins full inert dispatch and every direct seam import edge",()=>{
  expect(INERT_SIGNABLE_ADAPTERS.map(a=>a.kind)).toEqual(["counter"]);
  expect(Object.isFrozen(INERT_SIGNABLE_ADAPTERS)).toBe(true);
  expect(INERT_SIGNABLE_ADAPTERS.every(Object.isFrozen)).toBe(true);
  for(const [file,edges] of Object.entries(expectedImports))expect(imports(file),file).toEqual(edges);
  const calls:string[]=[];
  function visit(node:ts.Node){if(ts.isCallExpression(node)&&node.expression.getText()==="createRecordSigner")calls.push(node.arguments.map(a=>a.getText()).join(","));ts.forEachChild(node,visit);}
  visit(ast("signing/service.ts"));
  expect(calls).toEqual(["grant,provider,INERT_SIGNABLE_ADAPTERS[0].schema,INERT_SIGNABLE_ADAPTERS[0].kind"]);
});
it("pins native crash settlement bytes and excludes classifier paths from all live roots",()=>{
  expect(createHash("sha256").update(readFileSync("../castle-wall-daemon/src/business_profile/signer_service.rs")).digest("hex")).toBe("3ffd1c4c222db6620f064c1ea313d3eacdbef1956aff8f9abbe983ffa2fe5427");
  expect(createHash("sha256").update(readFileSync("src/signing/worker.ts")).digest("hex")).toBe("fabb257c2d06162ef567a06da8837762d7a7b71d141da7845fd8eecfbf327eb3");
  const files=readdirSync(sourceRoot,{recursive:true}).filter((n):n is string=>typeof n==="string"&&n.endsWith(".ts"));
  const edges=new Map(files.map(name=>[resolve(sourceRoot,name),dependencies(name).filter(s=>s.startsWith('.')).map(s=>resolve(sourceRoot,dirname(name),s.replace(/\.js$/,".ts")))]));
  const forbidden=["signing/custody-transaction.ts","signing/durable-store.ts","linux-business/activation-anchor.ts","signing/lifecycle.ts"].map(n=>resolve(sourceRoot,n));
  const roots=files.filter(n=>n.startsWith("cli/")||n.startsWith("wrap/")||!n.includes("/")||n.startsWith("mcp/")||n==="signing/worker.ts");
  const seen=new Set<string>();
  const walk=(file:string)=>{if(seen.has(file))return;seen.add(file);for(const child of edges.get(file)??[])walk(child);};
  roots.forEach(n=>walk(resolve(sourceRoot,n)));
  expect(forbidden.filter(n=>seen.has(n))).toEqual([]);
  for(const file of files){const source=ast(file);const declarations:string[]=[];function visit(node:ts.Node){if(ts.isClassDeclaration(node)&&node.name?.text==="InstalledBusiness")declarations.push(file);ts.forEachChild(node,visit);}visit(source);expect(declarations).toEqual([]);}
});
