'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const {spawnSync}=require('node:child_process');
const core=require('../assets/firewall-review-core.js');
global.window=global;require('../assets/firewall-review-demo.js');
const demo=global.FirewallReviewDemos;
const inspect=(s,v='auto')=>core.analyze(core.parse(s,v,XMLParser));
const codes=r=>r.findings.map(f=>f.code);
const rejects=(s,code,v='auto')=>assert.throws(()=>core.parse(s,v,XMLParser),e=>e.code===code);
// DOM-compatible adapter backed by Python's XML parser; native DOMParser is separately checked in the live browser.
class XMLParser {
  parseFromString(text){
    const py=`import sys,json,xml.etree.ElementTree as E
def dump(e):
 return {'name':e.tag,'attrs':e.attrib,'text':''.join(e.itertext()),'children':[dump(c) for c in e]}
try: print(json.dumps(dump(E.fromstring(sys.stdin.read()))))
except E.ParseError: print(json.dumps({'name':'parsererror','attrs':{},'text':'invalid','children':[]}))`;
    const p=spawnSync('python',['-c',py],{input:text,encoding:'utf8'});assert.equal(p.status,0);
    function make(n,parent=null){const el={localName:n.name,textContent:n.text,children:[],parentElement:parent,getAttribute:k=>n.attrs[k]??null,getElementsByTagName(name){return this.children.flatMap(c=>[...(c.localName===name?[c]:[]),...c.getElementsByTagName(name)]);}};el.children=n.children.map(c=>make(c,el));return el;}
    const root=make(JSON.parse(p.stdout));return {documentElement:root,getElementsByTagName:n=>[...(root.localName===n?[root]:[]),...root.getElementsByTagName(n)]};
  }
}
const policy=(id,fields='')=>`config firewall policy\nedit ${id}\nset srcintf "guest"\nset dstintf "servers"\nset srcaddr "all"\nset dstaddr "all"\nset service "ALL"\nset action accept\nset schedule "always"\n${fields}\nnext\nend`;
test('Fortinet: wide access and explicit settings are detected, disabled rules excluded',()=>{const r=inspect(demo.fortinet);assert.equal(r.counts.rules,4);assert.equal(r.counts.active,3);assert.equal(r.counts.high,1);assert.ok(codes(r).includes('potentialConflict'));assert.ok(!r.findings.some(f=>f.ruleId==='40'));});
test('Fortinet: missing defaults remain unknown',()=>{const r=inspect(policy(1));assert.equal(r.policies[0].logging,'unknown');assert.equal(r.policies[0].protection,'unknown');assert.ok(!codes(r).includes('noLogging'));assert.ok(!codes(r).includes('noProtection'));});
test('Fortinet: negated source is never treated as unrestricted',()=>{assert.ok(!codes(inspect(policy(1,'set srcaddr-negate enable'))).includes('anyAny'));});
test('Fortinet: deny does not become an allow finding',()=>{assert.ok(!codes(inspect(policy(1).replace('set action accept','set action deny'))).includes('anyAny'));});
test('Fortinet: VDOMs are isolated',()=>{const s='config vdom\nedit "A"\n'+policy(1)+'\nnext\nedit "B"\n'+policy(2)+'\nnext\nend';const r=inspect(s);assert.equal(r.counts.scopes,2);assert.ok(!codes(r).includes('potentialRedundancy'));});
test('FortiManager: packages are isolated',()=>{const s='config adom\nedit "root"\nconfig pkg\nedit "P1"\n'+policy(1)+'\nnext\nedit "P2"\n'+policy(2)+'\nnext\nend\nnext\nend';const r=inspect(s);assert.equal(r.counts.scopes,2);assert.ok(r.warnings.some(w=>w.code==='managerScope'));assert.ok(!codes(r).includes('potentialRedundancy'));});
test('Fortinet: address group with universal subnet resolves to Any',()=>{const objects='config firewall address\nedit "Universe"\nset subnet 0.0.0.0 0.0.0.0\nnext\nend\nconfig firewall addrgrp\nedit "Wide"\nset member "Universe"\nnext\nend\n';assert.ok(codes(inspect(objects+policy(1).replace('set srcaddr "all"','set srcaddr "Wide"'))).includes('anyAny'));});
test('Fortinet: policy names preserve quoted spaces',()=>{assert.equal(inspect(policy(1,'set name "Lab policy with spaces"')).policies[0].name,'Lab policy with spaces');});
test('Fortinet: a custom object named any is not the universal address',()=>{const s=policy(1).replace('set srcaddr "all"','set srcaddr "any"');assert.ok(!codes(inspect(s)).includes('anyAny'));});
test('Fortinet: malformed CLI rejected',()=>{rejects(policy(1).replace('\nnext\nend',''),'malformedCLI');});
test('Fortinet: missing selectors do not create broad or overlap findings',()=>{const r=inspect(policy(1).replace('set dstaddr "all"',''));assert.ok(!codes(r).includes('anyAny'));assert.ok(r.warnings.some(w=>w.code==='incompleteRules'));});
test('Check Point: real UID dictionary resolves action, criteria and tracking',()=>{const r=inspect(demo.checkpoint);assert.equal(r.counts.rules,3);assert.equal(r.policies[0].action,'accept');assert.equal(r.policies[0].logging,'off');assert.ok(codes(r).includes('potentialConflict'));});
test('Check Point: unresolved dictionary suppresses broad findings',()=>{const j=JSON.parse(demo.checkpoint);delete j['objects-dictionary'];const r=inspect(JSON.stringify(j));assert.equal(r.counts.high,0);assert.ok(r.warnings.some(w=>w.code==='unresolvedObjects'));});
test('Check Point: separate object JSON accepted even when selected first',()=>{const j=JSON.parse(demo.checkpoint),objects={objects:j['objects-dictionary']};delete j['objects-dictionary'];assert.equal(inspect([JSON.stringify(objects),JSON.stringify(j)]).counts.high,1);});
test('Check Point: nested sections retain layer scope',()=>{const j=JSON.parse(demo.checkpoint);j.rulebase=[{type:'access-section',uid:'section',name:'Section',rulebase:j.rulebase}];assert.equal(inspect(JSON.stringify(j)).counts.rules,3);});
test('Check Point: pagination is flagged',()=>{const j=JSON.parse(demo.checkpoint);j.total=10;assert.ok(inspect(JSON.stringify(j)).warnings.some(w=>w.code==='pagination'));});
test('Check Point: missing pages become complete when supplied, duplicate rules deduplicated',()=>{const j=JSON.parse(demo.checkpoint);const a={...j,rulebase:j.rulebase.slice(0,1),to:1},b={...j,rulebase:j.rulebase.slice(1),from:2};const r=inspect([JSON.stringify(a),JSON.stringify(b),JSON.stringify(a)]);assert.equal(r.counts.rules,3);assert.ok(!r.warnings.some(w=>w.code==='pagination'));});
test('Check Point: selected page order does not change rule evaluation order',()=>{const j=JSON.parse(demo.checkpoint);const a={...j,rulebase:j.rulebase.slice(0,1),to:1},b={...j,rulebase:j.rulebase.slice(1),from:2};const r=inspect([JSON.stringify(b),JSON.stringify(a)]);assert.equal(r.policies[0].id,'lab-cp-10');assert.ok(codes(r).includes('potentialConflict'));});
test('Check Point: source-negate suppresses broad finding',()=>{const j=JSON.parse(demo.checkpoint);j.rulebase=j.rulebase.slice(-1);j.rulebase[0]['source-negate']=true;assert.equal(inspect(JSON.stringify(j)).counts.high,0);});
test('Check Point: inline layer never treated as plain allow',()=>{const j=JSON.parse(demo.checkpoint);j.rulebase[2]['inline-layer']='layer';assert.equal(inspect(JSON.stringify(j)).counts.high,0);});
test('Check Point: disabled rules excluded',()=>{const j=JSON.parse(demo.checkpoint);j.rulebase.forEach(r=>r.enabled=false);assert.equal(inspect(JSON.stringify(j)).findings.length,0);});
test('PAN-OS: native XML structure and profile groups',()=>{const r=inspect(demo.paloalto);assert.equal(r.counts.rules,3);assert.equal(r.counts.high,1);assert.equal(r.policies[2].protection,'on');assert.ok(codes(r).includes('noLogging'));});
test('PAN-OS: named object all is not Any',()=>{const s=demo.paloalto.replaceAll('<member>any</member>','<member>all</member>');assert.equal(inspect(s).counts.high,0);});
test('PAN-OS: application-default is not all services',()=>{const s=demo.paloalto.replaceAll('<service><member>any</member></service>','<service><member>application-default</member></service>');assert.equal(inspect(s).counts.high,0);});
test('PAN-OS: omitted log settings remain unknown',()=>{const s=demo.paloalto.replaceAll('<log-start>no</log-start>','').replaceAll('<log-end>no</log-end>','').replaceAll('<log-end>yes</log-end>','');assert.ok(!codes(inspect(s)).includes('noLogging'));});
test('Panorama: pre/post/shared contexts are not merged',()=>{const body=demo.paloalto.match(/<security>[\s\S]*<\/security>/)[0];const s='<config><shared><pre-rulebase>'+body+'</pre-rulebase><post-rulebase>'+body+'</post-rulebase></shared></config>';const r=inspect(s);assert.equal(r.counts.scopes,2);assert.equal(r.counts.rules,6);});
test('PAN-OS: API config wrapper accepted',()=>{const s=demo.paloalto.replace('<?xml version="1.0"?>','');assert.equal(inspect('<response status="success"><result>'+s+'</result></response>').counts.rules,3);});
test('PAN-OS: malformed XML rejected',()=>rejects('<config><security></config>','malformedXML','paloalto'));
test('PAN-OS: XML entities rejected before parsing',()=>rejects('<!DOCTYPE config [<!ENTITY x "test">]><config/>','unsafeXML','paloalto'));
test('Input: malformed JSON rejected',()=>rejects('{"rulebase": invalid}','malformedJSON'));
test('Input: unrelated formats and empty configurations rejected',()=>{rejects('hello','unknownFormat');rejects('','empty');rejects('{"rulebase":[]}','noCheckPointRules');});
test('Input: file-count and size limits enforced',()=>{rejects([policy(1),policy(2)],'oneFile');rejects('x'.repeat(core.MAX_BYTES+1),'tooLarge');});
test('Diff: equivalent snapshots produce no changes',()=>{const m=core.parse(demo.fortinet);assert.deepEqual(core.diff(m,m),{added:[],removed:[],changed:[]});});
test('Diff: security changes reported separately from text',()=>{const a=core.parse(policy(1,'set logtraffic all')),b=core.parse(policy(1,'set logtraffic disable'));const d=core.diff(a,b);assert.equal(d.changed.length,1);assert.deepEqual(d.changed[0].changes.map(c=>c.field),['logging']);});
test('Diff: different vendors rejected',()=>assert.throws(()=>core.diff(core.parse(demo.fortinet),core.parse(demo.checkpoint)),e=>e.code==='vendorMismatch'));
test('Limits: large rulebase retains individual checks without quadratic overlap work',()=>{const parts=[];for(let i=0;i<351;i++)parts.push(policy(i));const r=inspect(parts.join('\n'));assert.equal(r.counts.rules,351);assert.ok(r.warnings.some(w=>w.code==='pairLimit'));});
test('Privacy: parsed report does not include unrelated passwords',()=>{const s='config system admin\nedit "admin"\nset password "DO_NOT_EXPORT_SECRET"\nnext\nend\n'+policy(1);assert.ok(!JSON.stringify(inspect(s)).includes('DO_NOT_EXPORT_SECRET'));});
