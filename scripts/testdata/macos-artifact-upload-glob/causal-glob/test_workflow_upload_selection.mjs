import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
const require=createRequire(import.meta.url);
const glob=require('@actions/glob');
const yaml=require('yaml');
const [workflowFile, scratch]=process.argv.slice(2);
assert(workflowFile && scratch,'actual workflow and fresh owned scratch directory are required');
assert.equal(require('@actions/glob/package.json').version,'0.5.0','matching pinned action glob engine required');
const workflow=yaml.parse(fs.readFileSync(workflowFile,'utf8'));
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const action=yaml.parse(fs.readFileSync(path.join(root,'resolved-action.yml'),'utf8'));
assert.equal(action.inputs['include-hidden-files'].default,'false');
fs.mkdirSync(scratch,{mode:0o700});
const source=path.join(scratch,'source');
const appRelative='vpn-control-macos-update-fixture/packages/base/fixture.app';
const app=path.join(source,appRelative);
fs.mkdirSync(path.join(app,'Contents','MacOS'),{recursive:true});
fs.mkdirSync(path.join(app,'Contents','app','.metadata'),{recursive:true});
fs.writeFileSync(path.join(app,'Contents','app','.jpackage.xml'),'<jpackage signed-resource="required"/>\n');
fs.writeFileSync(path.join(app,'Contents','app','.metadata','nested.bin'),'nested-required\n');
fs.writeFileSync(path.join(app,'Contents','app','dependency.jar'),'ordinary-required\n');
fs.writeFileSync(path.join(app,'Contents','Info.plist'),'<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>fixture</string><key>CFBundleIdentifier</key><string>com.kardinal.vpncontrol.uploadfixture</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>2.2.5</string></dict></plist>');
const isMac=process.platform==='darwin';
function command(args) {
  const result=spawnSync('/usr/bin/codesign',args,{encoding:'utf8'});
  if (result.error) throw result.error;
  return result;
}
if (isMac) {
  // Byte copying avoids propagating protected flags from a system input.
  fs.writeFileSync(path.join(app,'Contents','MacOS','fixture'),fs.readFileSync('/usr/bin/true'),{mode:0o755});
  const result=command(['--force','--deep','--sign','-',app]);
  assert.equal(result.status,0,result.stderr);
} else {
  fs.writeFileSync(path.join(app,'Contents','MacOS','fixture'),'portable-enumeration-input\n');
}
function clonedWorkflow(flag) {
  const clone=structuredClone(workflow);
  const step=uploadStep(clone);
  if (flag===undefined) delete step.with['include-hidden-files'];
  else step.with['include-hidden-files']=flag;
  return clone;
}
function uploadStep(document) {
  const candidates=Object.values(document.jobs).flatMap(job=>job.steps||[])
    .filter(step=>step.name==='Upload immutable fixture pair and provenance');
  if (candidates.length!==1 || candidates[0].uses!=='actions/upload-artifact@v4')
    throw Error('exact success-upload step required');
  return candidates[0];
}
async function select(document) {
  const step=uploadStep(document);
  const value=step.with['include-hidden-files'] ?? action.inputs['include-hidden-files'].default;
  const includeHidden=value===true || value==='true';
  if (![true,false,'true','false'].includes(value)) throw Error('boolean hidden-file policy required');
  const patterns=step.with.path.replaceAll('${{ runner.temp }}',source);
  // These options match the exact resolved v4.6.2 search.ts in the public proof.
  const finder=await glob.create(patterns,{followSymbolicLinks:true,implicitDescendants:true,
    omitBrokenSymbolicLinks:true,excludeHiddenFiles:!includeHidden});
  const matches=(await finder.glob()).filter(name=>!fs.statSync(name).isDirectory());
  return matches.map(name=>relativeMember(source,name)).sort();
}
const targetRelative='vpn-control-macos-update-fixture/packages/target/fixture.app';
const targetApp=path.join(source,targetRelative);
fs.mkdirSync(path.join(targetApp,'Contents','app'),{recursive:true});
fs.writeFileSync(path.join(targetApp,'Contents','app','.jpackage.xml'),'<target-required/>\n');
fs.writeFileSync(path.join(targetApp,'Contents','app','dependency.jar'),'target-ordinary-required\n');
function relativeMember(root,name,pathApi=path) {
  return pathApi.relative(root,name).split(pathApi.sep).join('/');
}
const required=[appRelative+'/Contents/app/.jpackage.xml',
  appRelative+'/Contents/app/.metadata/nested.bin',appRelative+'/Contents/app/dependency.jar',
  targetRelative+'/Contents/app/.jpackage.xml',targetRelative+'/Contents/app/dependency.jar'];
function requireComplete(names) {
  for (const name of required) assert(names.includes(name),'sealed fixture member missing: '+name);
}
function project(names,name) {
  const output=path.join(scratch,name);fs.mkdirSync(output,{mode:0o700});
  for (const relative of names) {
    assert(!relative.startsWith('..')&&!path.isAbsolute(relative));
    const input=path.join(source,relative), target=path.join(output,relative);
    fs.mkdirSync(path.dirname(target),{recursive:true});
    fs.copyFileSync(input,target);fs.chmodSync(target,fs.statSync(input).mode&0o777);
  }
  return path.join(output,appRelative);
}
test('portable: actual workflow preserves required sealed and ordinary members',async()=>{
  requireComplete(await select(workflow));
});
test('portable: actual action default excludes hidden members and fails completeness',async()=>{
  const names=await select(clonedWorkflow(undefined));
  assert(!names.includes(required[0]));
  assert.throws(()=>requireComplete(names),/sealed fixture member missing/);
});
test('portable: explicit false fails completeness without dropping ordinary dependency',async()=>{
  const names=await select(clonedWorkflow(false));
  assert(names.includes(required[2]));
  assert.throws(()=>requireComplete(names),/sealed fixture member missing/);
});
test('portable: explicit true preserves nested hidden directory and ordinary dependency',async()=>{
  requireComplete(await select(clonedWorkflow(true)));
  const winRoot='C:\\owned\\source';
  const winName=winRoot+'\\'+required[0].replaceAll('/','\\');
  assert.equal(relativeMember(winRoot,winName,path.win32),required[0]);
  assert.equal(relativeMember('/owned/source','/owned/source/'+required[0],path.posix),required[0]);
});
test('portable: wrong success-upload identity refuses before selection',async()=>{
  const clone=structuredClone(workflow);uploadStep(clone).uses='actions/download-artifact@v4';
  await assert.rejects(select(clone),/exact success-upload step required/);
});
test('macOS native: signed source bundle verifies',{skip:!isMac},()=>{
  const result=command(['--verify','--deep','--strict',app]);assert.equal(result.status,0,result.stderr);
});
test('macOS native: actual workflow projection preserves its signed bundle',{skip:!isMac},async()=>{
  const projected=project(await select(workflow),'actual-workflow-projection');
  const result=command(['--verify','--deep','--strict',projected]);
  assert.equal(result.status,0,result.stderr);
});
test('macOS native: retained but tampered sealed member remains rejected',{skip:!isMac},async()=>{
  const projected=project(await select(clonedWorkflow(true)),'tamper-projection');
  fs.writeFileSync(path.join(projected,'Contents','app','.jpackage.xml'),'<tampered/>\n');
  const result=command(['--verify','--deep','--strict',projected]);
  assert.equal(result.status,1);assert.match(result.stderr,/sealed resource/);
});
