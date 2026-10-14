// Trusted hosted-only orchestration. No existing signing/private key is read.
import {constants, openSync, closeSync, fstatSync, readSync, lstatSync, mkdirSync, readdirSync, realpathSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {spawnSync, spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export function readRegular(source) {
  const stat=lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink!==1 || stat.size>8*1024*1024) throw new Error('invalid Radar fixture source');
  const fd=openSync(source,constants.O_RDONLY|constants.O_NOFOLLOW);
  let bytes;
  try {
    const before=fstatSync(fd);
    if (before.dev!==stat.dev||before.ino!==stat.ino||before.size!==stat.size||before.nlink!==1) throw new Error('changed Radar fixture source');
    bytes=Buffer.alloc(stat.size);let offset=0;
    while(offset<bytes.length){const n=readSync(fd,bytes,offset,bytes.length-offset,offset);if(!n)throw new Error('truncated Radar fixture source');offset+=n;}
    const after=fstatSync(fd),current=lstatSync(source);
    if(after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||after.nlink!==1||current.isSymbolicLink()||current.ino!==after.ino||current.dev!==after.dev)throw new Error('changed Radar fixture source');
  } finally {closeSync(fd);}
  return bytes;
}
export function copyRegular(source,target) {
  const bytes=readRegular(source);
  mkdirSync(resolve(target,'..'),{recursive:true,mode:0o700});writeFileSync(target,bytes,{flag:'wx',mode:0o600});
}
export function stageEvidence(source, target, work) {
  const output=join(work,'output');
  const directories=[work,output,source].map(path=>{
    const stat=lstatSync(path);
    if(realpathSync(path)!==path||!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||!source.startsWith(output+'/'))throw new Error('invalid evidence directory');
    return [path,stat];
  });
  mkdirSync(target,{recursive:true,mode:0o700});
  for (const name of readdirSync(source).sort()) {
    if (name !== 'report.json' && !name.endsWith('.png')) continue;
    copyRegular(join(source,name),join(target,name));
  }
  for(const [path,initial] of directories){const after=lstatSync(path);if(after.dev!==initial.dev||after.ino!==initial.ino||after.isSymbolicLink()||realpathSync(path)!==path)throw new Error('evidence directory changed');}
}
export function validateStagedProof(proof,source,request) {
  const stat=lstatSync(proof);
  if(realpathSync(proof)!==proof||!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700)throw new Error('invalid staged proof root');
  const files=[];let encoded=0;
  const add=(path,relative,png)=>{
    const bytes=readRegular(path);encoded+=Math.ceil(bytes.length/3)*4;
    if(encoded>96*1024*1024||files.length>=512)throw new Error('Radar evidence exceeds limit');
    if(png&&!bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))throw new Error('invalid Radar PNG');
    files.push({path:relative,media_type:png?'image/png':'application/json',...(png?{}:{base64:bytes.toString('base64')})});
  };
  add(join(proof,'gate-receipt.json'),'gate-receipt.json',false);
  for(const name of ['territories','intelligence','signed-update']){
    const dir=join(proof,name),before=lstatSync(dir);
    if(realpathSync(dir)!==dir||!before.isDirectory()||before.isSymbolicLink()||before.uid!==process.getuid())throw new Error('invalid staged proof directory');
    for(const file of readdirSync(dir).sort()){
      if(file==='report.json'||file.endsWith('.png'))add(join(dir,file),name+'/'+file,file.endsWith('.png'));
      else throw new Error('unexpected staged proof file');
    }
    const after=lstatSync(dir);if(after.dev!==before.dev||after.ino!==before.ino||realpathSync(dir)!==dir)throw new Error('staged directory changed');
  }
  const after=lstatSync(proof);if(after.dev!==stat.dev||after.ino!==stat.ino||realpathSync(proof)!==proof)throw new Error('staged root changed');
  return validateRadarBundle({files},source,request);
}
export function validateRequest(source,request,head) {
  if(!/^[0-9a-f]{40}$/.test(source??'')||!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request??'')||head!==source)throw new Error('invalid Radar source/request binding');
}
export const territorySteps = ["Start und Sidebar","Lage","Gebiete","Stadtprofil + Quote","Zielprofil","Bezirksprofil + Ansatzpunkt","KI-Gebietsanalyse","Level-Aufstieg","Aufträge + Sichtung","CRM","Karte: leer bis zur Suche, Ebenen, Gebiet anklicken","Suchleiste + Mein Standort + Umkreis-Analyse","Karte im Gebiet + Firmenakte","Merkliste","Suchprofile","Sales-Liste","Firmenakte Einordnung","Geräte","Gebiet importieren + 409","Zentrale","Leerer Arbeitsbereich","Schreibgeschützt"];
export const territoryViews = ["lage","gebiete","stadtprofil","dialog-quote","dialog-zielprofil","bezirksprofil","ki-analyse","level-aufstieg","auftraege","sichtung","crm","dialog-deal","karte-ebenen","karte-gebiet","suchleiste-offen","mein-standort-analyse","mein-standort-abgelehnt","karte","firmenakte","merkliste","suchprofile","sales-listen","sales-liste-schritt","firmenakte-einordnung","geraete","geraete-schublade","karte-geraete","geraete-server-adresse","dialog-gebiet-hinzufuegen","neues-gebiet","dialog-zentrale","leer","leer-gebiete","readonly","readonly-stadtprofil","readonly-firmenakte"];
export const intelligenceShots = ["empty-workspace-catalog","hamburg-without-other-filters","shared-radius-filter","infrastructure-profile","watchlist-note","dismissed-company","company-detail","research-running","research-report","research-persisted","crm-cohort","sourced-relationships","saved-searches","shared-list-crm-task","devices-all-types","hamburg-server-source","automatic-device-location","device-service-failure","viewer-readonly","workbench-workspace-boundary"];
export const intelligenceStressShots = ["literal-empty-search","catalog-service-error","catalog-auth-error","catalog-malformed-response","research-queue-error","workspace-switch-race","accounts-permission-error"];
export const intelligenceAnchors = ["real WebGL map and deck render","map and list send identical canonical filter contract","stored report reopens after reload without rerunning research","CRM cohort exposes exact sample and retrospective boundary","small cohort displays insufficient state without invented percentage","sales CAS conflict does not falsely persist new status","next action is canonical CRM activity with linked owner","real click completes CRM task using valid idempotency key","real deck icon layer positions seven devices and omits unknown position","all eight device types retain icon and list entry","consented device reports its OS fix automatically, without any click in Radar","late automatic OS fix cannot send coordinates after the workspace switch","workspace switch drops previous profiles and notices","no unexpected console or page errors","no unexpected transport failure"];
export const signedChecks = ["install stages v1 without hot replacement","signed actual Radar v1 mounted through real loader","v1 causes no automatic OS location request","actual v1 button is denied honestly by the host before any OS call","search and sort persisted in workspace before update","v2 staged while v1 view stays mounted","unsaved note blocks update reload","actual Radar v2 runs without rebuilding host","filters restored across plugin update","same workspace envelopes and sort survive update","restored search and sort reach catalog request","shared note survives plugin update","expanded permission does not itself request OS location","explicit v2 button passes the signed host permission gate exactly once","search centering does not report a fleet location","signed plugin renders workspace server without a personal owner","server site is approximate and denied device capabilities hide mutation controls","no page or console errors"];
export const signedShots = ['location-permission-denied','radar-v2','location-permission-expanded','workspace-server'];
export function validateRadarBundle(bundle,source,request) {
  validateRequest(source,request,source);
  const json=path=>{const file=bundle.files.find(f=>f.path===path);if(!file)throw new Error('missing Radar report');return JSON.parse(Buffer.from(file.base64,'base64'));};
  const gate=json('gate-receipt.json');
  if(gate.sourceSha!==source||gate.requestId!==request||gate.proofExit!==0||gate.fullMatricesRequested!==true)throw new Error('Radar receipt binding mismatch');
  const territories=['chromium-dark-1440','chromium-dark-390','chromium-dark-588','chromium-light-1440','chromium-light-390','chromium-light-588','webkit-dark-1440'];
  const intelligence=['chromium-dark-1440','chromium-dark-390','chromium-light-1440','chromium-light-390','webkit-dark-1440','webkit-dark-390','webkit-light-1440','webkit-light-390'];
  for(const [name,tags,key] of [['territories',territories,'cases'],['intelligence',intelligence,'runs']]) {
    const report=json(name+'/report.json'),rows=report[key],assertions=report.assertions;
    if(report.dodMet!==true||report.failed!==0||report.requestedCases!==null||!Array.isArray(rows)||rows.length!==tags.length||JSON.stringify(rows.map(r=>r.tag).sort())!==JSON.stringify([...tags].sort())||!Array.isArray(assertions)||!assertions.length||assertions.some(a=>a.ok!==true)||report.passed!==assertions.length)throw new Error('Radar full matrix not proven');
    const identities=assertions.map(a=>JSON.stringify([a.case??a.run,a.name]));
    if(identities.some((id,i)=>identities.indexOf(id)!==i))throw new Error('duplicate Radar assertion identity');
    if(name==='territories'&&(report.network!==false||(!/^[0-9a-f]{7,40}$/.test(report.git?.head??'')||!source.startsWith(report.git.head)||!Array.isArray(report.git.dirty)||report.git.dirty.length)))throw new Error('Radar territory source/network mismatch');
    if(name==='intelligence'&&report.scope!=='full-matrix')throw new Error('Radar matrix scope mismatch');
    const expectedImages=[];
    for(const row of rows){
      const own=assertions.filter(a=>(a.case??a.run)===row.tag);
      const required=name==='territories'?['0 Konsolen- und Seitenfehler','keine Fixture-Antwort ≥400 außer angekündigten','keine unerwarteten externen Anfragen','keine Transportfehler']:intelligenceAnchors;
      if(required.some(n=>!own.some(a=>a.name===n))||own.length<(name==='territories'?148:125))throw new Error('Radar required assertions absent');
      if(name==='territories'){
        if(report.scope!=='volle Matrix'||!Array.isArray(row.steps)||JSON.stringify(row.steps.map(s=>s.name))!==JSON.stringify(territorySteps)||row.steps.some(s=>s.ok!==true)||JSON.stringify(Object.keys(row.views??{}).sort())!==JSON.stringify([...territoryViews].sort()))throw new Error('Radar territory steps/views absent');
        for(const view of territoryViews)for(const suffix of ['kein horizontaler Überlauf','Overlays/Dialoge vollständig im Plugin-Rahmen','reduzierte Bewegung ohne laufende Animationen','Layoutblöcke überlappen nicht'])if(!own.some(a=>a.name===view+': '+suffix))throw new Error('Radar view assertion absent');
        expectedImages.push(...[...territoryViews,'import-409'].map(v=>name+'/'+row.tag+'-'+v+'.png'));
      }else{
        if(row.realTiles!==false||row.exception)throw new Error('Radar deterministic case invalid');
        expectedImages.push(...[...intelligenceShots,...(row.tag==='chromium-dark-1440'?intelligenceStressShots:[])].map(v=>name+'/'+row.tag+'-'+v+'.png'));
      }

      if(['consoleErrors','pageErrors','unexpectedRequests'].some(k=>!Array.isArray(row[k]??[])||(row[k]??[]).length)||!assertions.some(a=>(a.case??a.run)===row.tag)||!bundle.files.some(f=>f.path.startsWith(name+'/'+row.tag+'-')&&f.media_type==='image/png'))throw new Error('Radar case evidence missing or erroneous');
    }
    const actualImages=bundle.files.filter(f=>f.path.startsWith(name+'/')&&f.media_type==='image/png').map(f=>f.path);
    if(JSON.stringify(actualImages.sort())!==JSON.stringify(expectedImages.sort()))throw new Error('Radar screenshot set incomplete or duplicated');
    if(name==='intelligence'){
      if(!Array.isArray(report.screenshots)||JSON.stringify(report.screenshots.map(r=>name+'/'+r.run+'-'+r.name+'.png').sort())!==JSON.stringify(expectedImages.sort())||!assertions.some(a=>a.run==='harness'&&a.name==='all nonlocal non-tile requests prevented and none attempted'))throw new Error('Radar screenshot manifest absent');
    }
    if((report.unexpectedRequests??[]).length)throw new Error('Radar unexpected request');
  }
  const signed=json('signed-update/report.json');
  if(signed.sourceCommit!==source||signed.failure||!Array.isArray(signed.errors)||signed.errors.length||!Array.isArray(signed.checks)||signed.checks.length===0||signed.checks.some(c=>c.ok!==true))throw new Error('signed Radar proof failed');
  const expectedChecks=['chromium','webkit'].flatMap(e=>signedChecks.map(n=>e+': '+n));
  const expectedImages=['chromium','webkit'].flatMap(e=>signedShots.map(n=>'signed-update/'+e+'-'+n+'.png'));
  if(JSON.stringify(signed.checks.map(c=>c.name).sort())!==JSON.stringify(expectedChecks.sort())||JSON.stringify(bundle.files.filter(f=>f.path.startsWith('signed-update/')&&f.media_type==='image/png').map(f=>f.path).sort())!==JSON.stringify(expectedImages.sort())||!['bundleSha256','hostHtmlSha256'].every(k=>/^[0-9a-f]{64}$/.test(signed[k]??'')))throw new Error('signed Radar exact evidence absent');
  if(!Array.isArray(signed.restoredState)||JSON.stringify(signed.restoredState.map(r=>r.engineName).sort())!==JSON.stringify(['chromium','webkit']))throw new Error('signed Radar restored state absent');
  for(const row of signed.restoredState){
    if(!Array.isArray(row.before)||row.before.length!==2||JSON.stringify(row.before)!==JSON.stringify(row.after))throw new Error('signed Radar state not restored');
    for(const suffix of ['filters','sort']){const item=row.before.find(i=>i.key.endsWith('radar%3A'+suffix));if(!item||!item.key.includes('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')||item.envelope?.version!==1||(suffix==='filters'?item.envelope.value?.q!=='Meridian':item.envelope.value!=='name'))throw new Error('signed Radar persisted state invalid');}
  }
  return true;
}
// Die Radar-Browsermatrix (Gebiete: 12 Fälle, ~1.900 Prüfungen) braucht seit den 3D-Städten
// lokal schon ~19 min; 20 min pro Befehl reichten auf CI-Runnern nicht mehr (Exit 124).
export function runCommand(command,args,options,timeoutMs=40*60*1000) {
  return new Promise((resolve,reject)=>{
    const child=spawn(command,args,{...options,detached:true});let timedOut=false;
    const kill=()=>{try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}};
    const timer=setTimeout(()=>{timedOut=true;kill();},timeoutMs);
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('close',code=>{clearTimeout(timer);kill();resolve({status:timedOut?124:code??70});});
  });
}
export function proofCommands(work) {
  const source=join(work,'source'), output=join(work,'output');
  return [
    ['rustup',['target','add','wasm32-unknown-unknown']],
    ['cargo',['install','wasm-bindgen-cli','--version','0.2.126','--locked','--root',join(work,'tools')]],
    ['sudo',['apt-get','install','-y','minisign']],
    ['minisign',['-G','-W','-s',join(work,'fixture.sec'),'-p',join(work,'fixture.pub')]],
    ['node',[join(source,'scripts/plugins/build-policy-wasm.mjs'),'--test']],
    ['node',['scripts/plugins/build-plugin.mjs','radar',join(work,'bundles')]],
    ['node',['scripts/verify-radar-territories.mjs']],
    ['node',['scripts/verify-radar-intelligence.mjs']],
    ['bun',['--no-env-file','scripts/verify-radar-plugin-update.mjs']],
  ];
}
async function run(work,proof) {
  const root=process.cwd(), temp=realpathSync(process.env.RUNNER_TEMP);
  for (const p of [work,proof]) {
    const s=lstatSync(p);
    if (p!==realpathSync(p)||!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700||!p.startsWith(temp+'/')||p.startsWith(root+'/')||readdirSync(p).length) throw new Error('fresh owned canonical proof roots required');
  }
  const head=spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'});
  validateRequest(process.env.SOURCE_SHA,process.env.REQUEST_ID,head.stdout?.trim());
  const clean=()=>{const r=spawnSync('git',['status','--porcelain','--untracked-files=all'],{encoding:'utf8'});if(r.status!==0||r.stdout.trim())throw new Error('Radar checkout not clean');};
  clean();
  const source=join(work,'source');
  for (const path of ['Cargo.toml','Cargo.lock','fixtures/public-key.txt','fixtures/vectors.json','fixtures/generate.py']) copyRegular(join(root,'crates/scai-plugin-policy',path),join(source,'crates/scai-plugin-policy',path));
  for (const name of readdirSync(join(root,'crates/scai-plugin-policy/src'))) copyRegular(join(root,'crates/scai-plugin-policy/src',name),join(source,'crates/scai-plugin-policy/src',name));
  copyRegular(join(root,'scripts/plugins/build-policy-wasm.mjs'),join(source,'scripts/plugins/build-policy-wasm.mjs'));
  const output=join(work,'output');
  for (const name of ['territories','intelligence','signed-update']) mkdirSync(join(output,name),{recursive:true,mode:0o700});
  const env={...process.env,SCAI_WASM_BINDGEN_CLI:join(work,'tools/bin/wasm-bindgen'),TMPDIR:work,
    RADAR_PROOF_OUT:join(output,'territories'),
    RADAR_UPDATE_PROOF_OUT:join(output,'signed-update'),RADAR_UPDATE_PROOF_SOURCE:join(work,'bundles/radar'),
    SCAI_PROOF_SIGNING_KEY:join(work,'fixture.sec'),SCAI_RADAR_FIXTURE_ROOT:work};
  for (const key of ['RADAR_PROOF_CASE','RADAR_PROOF_NETWORK','RADAR_REAL_TILES','RADAR_PROOF_BASE','RADAR_INTELLIGENCE_PROOF_CASE','RADAR_INTELLIGENCE_PROOF_BASE','RADAR_PROOF_NEXUS_QUERY_MODULE','SCAI_WASM_BINDGEN_CLI']) delete env[key];
  env.SCAI_WASM_BINDGEN_CLI=join(work,'tools/bin/wasm-bindgen');
  let status=0; const completed=[];
  try {
    for (const [command,args] of proofCommands(work)) {
      if (command==='node' && args[0]===join(source,'scripts/plugins/build-policy-wasm.mjs')) {
        const publicKey=readFileSync(join(work,'fixture.pub'),'utf8').trim().split('\n').at(-1);
        writeFileSync(join(source,'crates/scai-plugin-policy/fixtures/public-key.txt'),publicKey+'\n');
      }
      const commandEnv = {...env, RADAR_PROOF_OUT:join(output,args[0]==='scripts/verify-radar-intelligence.mjs'?'intelligence':'territories')};
      const result=await runCommand(command,args,{cwd:root,env:commandEnv,stdio:'inherit'});
      if (result.status!==0) {status=result.status ?? 70;break;}
      completed.push(args[0]);
    }
  } finally {
    for (const name of ['territories','intelligence','signed-update']) stageEvidence(join(output,name),join(proof,name),work);
    writeFileSync(join(proof,'gate-receipt.json'),JSON.stringify({sourceSha:process.env.SOURCE_SHA,requestId:process.env.REQUEST_ID,proofExit:status,fullMatricesRequested:true,completedCommands:completed,realProvider:false,productionKeysRead:false})+'\n');
  }
  clean();
  if(status===0)validateStagedProof(proof,process.env.SOURCE_SHA,process.env.REQUEST_ID);
  return status;
}
if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {process.exitCode=await run(...process.argv.slice(2));} catch(error) {console.error(error);process.exitCode=70;}
}
