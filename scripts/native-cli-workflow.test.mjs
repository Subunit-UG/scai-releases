import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,chmodSync,realpathSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import test from 'node:test';
import {sealPrivateProof} from './seal-private-proof.mjs';
import {NATIVE_CLI_WORKFLOW} from './native-cli-workflow-policy.mjs';
import {validateSourceConfidentiality} from './verify-source-confidentiality.mjs';
import {validateNativeCliProofMode,validateNativeCliRequest} from './validate-native-cli-request.mjs';
const workflow='native-cli-hermetic.yml';
const files=['sonar-build.yml','pr-check.yml','build-all.yml','windows-arm-smoke.yml','u1-chat-pr-check.yml','auth-pr-check.yml','atlas-pr-check.yml','fleet-source-check.yml',workflow];
const fixtures=Object.fromEntries(files.map(name=>[name,readFileSync(new URL(`../.github/workflows/${name}`,import.meta.url),'utf8')]));
const selector=readFileSync(new URL('./validate-release-assets.sh',import.meta.url),'utf8');
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:3072});const publicBase64=Buffer.from(publicKey.export({type:'spki',format:'pem'})).toString('base64');
const sha='a'.repeat(40),request='11111111-1111-4111-8111-111111111111';
test('current exact manual workflow and required public request pass',()=>{
 assert.equal(fixtures[workflow],NATIVE_CLI_WORKFLOW);assert.deepEqual(validateSourceConfidentiality(fixtures,selector),[]);assert.equal(validateNativeCliRequest(sha,request,publicBase64).source_sha,sha);
});
for(const [name,s,r,key] of [['mutable source','main',request,publicBase64],['invalid UUID',sha,'not-uuid',publicBase64],['absent recipient',sha,request,''],['private PEM',sha,request,Buffer.from(privateKey.export({type:'pkcs8',format:'pem'})).toString('base64')],['malformed recipient',sha,request,'not-base64!']])test(`request rejects ${name}`,()=>assert.throws(()=>validateNativeCliRequest(s,r,key)));
test('weak RSA recipient rejected',()=>{const {publicKey:key}=generateKeyPairSync('rsa',{modulusLength:2048});assert.throws(()=>validateNativeCliRequest(sha,request,Buffer.from(key.export({type:'spki',format:'pem'})).toString('base64')));});
for(const [name,before,after] of [
 ['untyped proof mode','type: choice','type: string'],
 ['unsafe default','default: success','default: late-a-failure-discovery'],
 ['arbitrary mode option','          - late-a-failure-discovery','          - arbitrary'],
 ['mode missing before checkout','      SCAI_NATIVE_CLI_PROOF_MODE: ${{ inputs.proof_mode }}',''],
 ['automatic trigger','  workflow_dispatch:','  push:'],
 ['non ARM runner','runs-on: macos-15','runs-on: ubuntu-latest'],
 ['unbounded timeout','timeout-minutes: 10','timeout-minutes: 60'],
 ['credentials retained','persist-credentials: false','persist-credentials: true'],
 ['request validation skipped','node gate/scripts/validate-native-cli-request.mjs','echo skipped'],
 ['wrong private repo','git@github.com:Subunit-UG/scai-app.git','git@github.com:attacker/source.git'],
 ['mutable checkout','"$SOURCE_SHA"','main'],
 ['failure ignored','id: native_cli_proof','id: native_cli_proof\n        continue-on-error: true'],
 ['proof skipped','id: native_cli_proof','id: native_cli_proof\n        if: false'],
 ['plaintext proof','run-confidential.sh" native-cli-proof','echo" native-cli-proof'],
 ['raw logs uploaded','path: ${{ runner.temp }}/scai-native-cli-encrypted-proof.json','path: ${{ runner.temp }}/scai-confidential-logs/'],
 ['key missing','SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}',"SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ''"],
 ['long retention','retention-days: 1','retention-days: 90'],
 ['duplicate extra step','    steps:','    steps:\n      - run: echo bypass'],
 ['public failure diagnostic',"if: failure() && steps.native_cli_proof.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",'if: always()'],
])test(`workflow rejects ${name}`,()=>{assert.ok(fixtures[workflow].includes(before));assert.ok(validateSourceConfidentiality({...fixtures,[workflow]:fixtures[workflow].replace(before,after)},selector).some(e=>e.startsWith(workflow+':')));});
for(const [mode,code] of [[undefined,0],['success',37],['late-a-failure-discovery',37]])test(`trusted wrapper isolates synthetic Python fixture ${mode??'default'} and preserves ${code}`,()=>{
 const temp=realpathSync(mkdtempSync(join(tmpdir(),'native-wrapper-synthetic-'))),bin=join(temp,'bin'),cwd=join(temp,'source');mkdirSync(bin);mkdirSync(cwd);mkdirSync(join(cwd,'scripts'));
 writeFileSync(join(bin,'uname'),'#!/usr/bin/env bash\nif [[ "$1" == -s ]]; then echo Darwin; else echo arm64; fi\n');chmodSync(join(bin,'uname'),0o700);
 writeFileSync(join(cwd,'scripts','verify-native-cli-hermetic.py'),`import os,json,pathlib,sys\nr=pathlib.Path(os.environ['SCAI_NATIVE_CLI_PROOF_ROOT'])\nassert not list(r.iterdir())\n(r/'inside').mkdir()\n(r/'inside'/'cli-owned-symlink').symlink_to('/synthetic-nonexistent-canary')\nassert 'SOURCE_DEPLOY_KEY' not in os.environ\nassert 'SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64' not in os.environ\nassert 'CANARY_HOST_ENV' not in os.environ\nassert os.environ['HOME']!=os.environ['SCAI_NATIVE_HOST_HOME']\nassert sys.argv[1:]==${JSON.stringify(mode==='late-a-failure-discovery'?['--icu','--late-a-failure-discovery']:['--icu'])}\nassert 'SCAI_NATIVE_CLI_PROOF_MODE' not in os.environ\n(r/'receipt.json').write_text(json.dumps({'sourceSha':os.environ['SOURCE_SHA'],'requestId':os.environ['REQUEST_ID'],'status':'PASS' if ${code}==0 else 'BLOCKED','synthetic':True}))\nraise SystemExit(${code})\n`);
 const output=join(temp,'outputs'),r=spawnSync('bash',[new URL('./run-native-cli-proof.sh',import.meta.url).pathname],{cwd,encoding:'utf8',env:{...process.env,...(mode===undefined?{}:{SCAI_NATIVE_CLI_PROOF_MODE:mode}),PATH:`${bin}:${process.env.PATH}`,RUNNER_TEMP:temp,GITHUB_OUTPUT:output,SOURCE_SHA:sha,REQUEST_ID:request,SOURCE_DEPLOY_KEY:'',GIT_SSH_COMMAND:'',CANARY_HOST_ENV:'do-not-inherit',SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64:publicBase64}});
 assert.equal(r.status,code,r.stderr);assert.equal(readFileSync(output,'utf8'),'encrypted_visual_receipt=true\n');assert.equal(r.stdout,'');const envelope=JSON.parse(readFileSync(join(temp,'scai-native-cli-encrypted-proof.json')));assert.ok(envelope.ciphertext);assert.equal('files' in envelope,false);
});
for(const [repo,status] of [['git@github.com:Subunit-UG/scai-app.git',65],['git@github.com:Subunit-UG/infra-atlas.git',64]])test(`SCAI checkout allowlist fails closed for ${repo}`,()=>{
 const r=spawnSync('bash',[new URL('./checkout-private-source.sh',import.meta.url).pathname,'subunit-scai',repo,sha],{encoding:'utf8',env:{...process.env,SOURCE_DEPLOY_KEY:''}});assert.equal(r.status,status);assert.doesNotMatch(r.stdout+r.stderr,/fetch|PRIVATE/);
});

test('successful native receipt cannot be absent, failed, or bound to another request',()=>{
 const temp=realpathSync(mkdtempSync(join(tmpdir(),'native-receipt-boundary-'))),root=join(temp,'proof');mkdirSync(root,{mode:0o700});
 const oldSource=process.env.SOURCE_SHA,oldRequest=process.env.REQUEST_ID;
 process.env.SOURCE_SHA=sha;process.env.REQUEST_ID=request;
 try {
  assert.throws(()=>sealPrivateProof(root,'native-cli',0,temp,publicBase64));
  for(const bad of [{status:'BLOCKED',sourceSha:sha,requestId:request},{status:'PASS',sourceSha:'b'.repeat(40),requestId:request},{status:'PASS',sourceSha:sha,requestId:'22222222-2222-4222-8222-222222222222'}]){
   writeFileSync(join(root,'receipt.json'),JSON.stringify(bad));assert.throws(()=>sealPrivateProof(root,'native-cli',0,temp,publicBase64));
  }
  writeFileSync(join(root,'receipt.json'),JSON.stringify({status:'PASS',sourceSha:sha,requestId:request}));assert.equal(sealPrivateProof(root,'native-cli',0,temp,publicBase64),join(temp,'scai-native-cli-encrypted-proof.json'));
 } finally {if(oldSource===undefined)delete process.env.SOURCE_SHA;else process.env.SOURCE_SHA=oldSource;if(oldRequest===undefined)delete process.env.REQUEST_ID;else process.env.REQUEST_ID=oldRequest;}
});

for(const mode of ['success','late-a-failure-discovery'])test(`exact proof mode ${mode} accepted`,()=>{assert.equal(validateNativeCliProofMode(mode),mode);assert.equal(validateNativeCliRequest(sha,request,publicBase64,mode).source_sha,sha);});
for(const mode of ['', 'unknown', 'SUCCESS', 'success\n', '--icu', '$(touch injected)', 'success; echo injected', null, 1])test(`proof mode rejects ${JSON.stringify(mode)} before request and wrapper launch`,()=>{
 assert.throws(()=>validateNativeCliProofMode(mode));assert.throws(()=>validateNativeCliRequest(sha,request,publicBase64,mode));
 if(typeof mode==='string'){
  const temp=realpathSync(mkdtempSync(join(tmpdir(),'native-invalid-mode-'))),bin=join(temp,'bin');mkdirSync(bin);
  writeFileSync(join(bin,'uname'),'#!/usr/bin/env bash\nif [[ "$1" == -s ]]; then echo Darwin; else echo arm64; fi\n');chmodSync(join(bin,'uname'),0o700);
  const r=spawnSync('bash',[new URL('./run-native-cli-proof.sh',import.meta.url).pathname],{encoding:'utf8',env:{...process.env,PATH:`${bin}:${process.env.PATH}`,RUNNER_TEMP:temp,SOURCE_SHA:sha,REQUEST_ID:request,SOURCE_DEPLOY_KEY:'',GIT_SSH_COMMAND:'',SCAI_NATIVE_CLI_PROOF_MODE:mode,SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64:publicBase64}});
  assert.equal(r.status,64);assert.equal(r.stdout,'');
 }
});
