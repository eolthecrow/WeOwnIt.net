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
const ngfwSample=`config firewall security-policy
    edit 2
        set name "allow-QA-Facebook"
        set srcintf "port18"
        set dstintf "port17"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set application 15832
        set groups "Dev" "QA"
    next
    edit 4
        set name "allow-QA-Email"
        set srcintf "port18"
        set dstintf "port17"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set url-category 23
        set groups "QA"
    next
end`;
test('Fortinet NGFW: supplied security-policy example detected with criteria preserved',()=>{
  for(const vendor of ['auto','fortinet']){
    const r=inspect(ngfwSample,vendor);assert.equal(r.counts.rules,2);
    assert.equal(r.policies[0].name,'allow-QA-Facebook');assert.deepEqual(r.policies[0].apps,['15832']);
    assert.deepEqual(r.policies[0].users,['Dev','QA']);assert.deepEqual(r.policies[1].urlCategories,['23']);
    assert.deepEqual(r.policies[0].service,[]);assert.equal(r.policies[0].logging,'unknown');assert.equal(r.policies[0].protection,'unknown');
    assert.equal(r.counts.high,0);assert.equal(r.counts.low,2);assert.ok(r.warnings.some(w=>w.code==='fortinetNGFW'));
    assert.ok(!codes(r).some(c=>['anyAny','broadAllow','potentialRedundancy','potentialConflict'].includes(c)));
  }
});
test('Fortinet NGFW: explicit ALL service still excludes broad/overlap inference',()=>{
  const s=ngfwSample.replaceAll('set schedule "always"','set schedule "always"\nset service "ALL"\nset logtraffic disable');
  const r=inspect(s);assert.equal(r.counts.high,0);assert.equal(r.findings.filter(f=>f.code==='noLogging').length,2);
  assert.ok(r.policies.every(p=>p.complex));assert.ok(!codes(r).includes('potentialRedundancy'));
});
test('Fortinet NGFW: regular and security rule IDs/order remain isolated in each VDOM',()=>{
  const s=policy(2)+'\n'+ngfwSample+'\n'+policy(3);
  const m=core.parse('config vdom\nedit A\n'+s+'\nnext\nedit B\n'+ngfwSample+'\nnext\nend');
  assert.equal(m.rules.length,6);assert.deepEqual(m.scopes,['A','A/security-policy','B/security-policy']);
  const n=core.parse(JSON.stringify(core.snapshot(m)));assert.deepEqual(core.diff(m,n),{added:[],removed:[],changed:[]});
});
test('Fortinet NGFW: JSON/XML snapshots retain categories and differences',()=>{
  const m=core.parse(ngfwSample),changed=core.parse(ngfwSample.replace('url-category 23','url-category 24'));
  assert.deepEqual(core.diff(m,changed).changed[0].changes.map(c=>c.field),['urlCategories']);
  for(const s of [JSON.stringify(core.snapshot(m)),core.snapshotXML(m)]){
    const n=core.parse(s,'auto',XMLParser);assert.deepEqual(core.snapshot(n).policies,core.snapshot(m).policies);assert.equal(core.analyze(n).counts.high,0);
  }
});
test('Fortinet NGFW: legacy snapshots load; malformed new selectors rejected',()=>{
  const s=core.snapshot(core.parse(policy(1)));for(const p of s.policies)for(const k of ['urlCategories','appCategories','appGroups','src6','dst6','inspectionProfiles'])delete p[k];
  assert.equal(core.parse(JSON.stringify(s)).rules.length,1);
  s.policies[0].urlCategories='23';rejects(JSON.stringify(s),'invalidSnapshot');
  const xml=core.snapshotXML(core.parse(ngfwSample)).replace('<urlCategories>','<urlCategories></urlCategories><urlCategories>');rejects(xml,'invalidSnapshot');
});
test('Fortinet NGFW: categories, group names, IPv6 and profile references preserved without simulation',()=>{
  const s=ngfwSample.replace('set application 15832','set application 15832\nset app-category 5 6\nset app-group "Business Apps"\nset users "alice"\nset srcaddr6 "IPv6 Clients"\nset dstaddr6 "all"\nset av-profile "AV & Inspection"');
  const p=inspect(s).policies[0];assert.deepEqual(p.appCategories,['5','6']);assert.deepEqual(p.appGroups,['Business Apps']);assert.deepEqual(p.users,['Dev','QA','alice']);assert.deepEqual(p.src6,['IPv6 Clients']);assert.equal(p.protection,'on');
  assert.equal(core.parse(core.snapshotXML(core.parse(s)),'auto',XMLParser).rules[0].inspectionProfiles[0],'av-profile:AV & Inspection');
});
test('Fortinet NGFW: malformed security-policy blocks rejected',()=>rejects(ngfwSample.replace(/end$/,''),'malformedCLI'));
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

const fortJSON=(policies,extra={})=>JSON.stringify({http_method:'GET',status:'success',http_status:200,vdom:'root',path:'firewall',name:'policy',results:policies,...extra});
const fortPolicy=(id=1)=>({policyid:id,name:'Wide access',srcintf:[{name:'any'}],dstintf:[{name:'any'}],srcaddr:[{name:'all'}],dstaddr:[{name:'all'}],service:[{name:'ALL'}],action:'accept',schedule:'always',logtraffic:'disable','utm-status':'disable'});
test('Fortinet NGFW JSON: security-policy endpoint retains numeric IDs and identity selectors',()=>{
  const p=fortPolicy(2);p.application=[{id:15832}];p['url-category']=[{id:23}];p.groups=[{name:'QA'}];delete p.service;
  const r=inspect(fortJSON([p],{name:'security-policy'}));assert.equal(r.counts.rules,1);assert.equal(r.policies[0].scope,'root/security-policy');assert.deepEqual(r.policies[0].apps,['15832']);assert.deepEqual(r.policies[0].urlCategories,['23']);assert.deepEqual(r.policies[0].users,['QA']);assert.equal(r.policies[0].orderKnown,false);assert.equal(r.counts.high,0);
  const mixed=inspect([fortJSON([fortPolicy(2)]),fortJSON([p],{name:'security-policy'})]);assert.equal(mixed.counts.rules,2);assert.equal(mixed.counts.scopes,2);
});
const paEntry=(name='Wide access')=>({'@name':name,'@location':'vsys','@vsys':'vsys1',from:{member:['any']},to:{member:['any']},source:{member:['any']},destination:{member:['any']},application:{member:['any']},service:{member:['any']},action:'allow','log-start':'no','log-end':'no'});
const paCLI=(name='Wide access',extra='')=>['from','to','source','destination','application','service'].map(k=>`set rulebase security rules "${name}" ${k} any`).join('\n')+`\nset rulebase security rules "${name}" action allow\nset rulebase security rules "${name}" log-start no\nset rulebase security rules "${name}" log-end no\n`+extra;
const paJSON=entry=>JSON.stringify({config:{devices:{entry:{'@name':'localhost.localdomain',vsys:{entry:{'@name':'vsys1',rulebase:{security:{rules:{entry:[entry]}}}}}}}}});
test('Fortinet JSON: native API response detected and mapped',()=>{const r=inspect(fortJSON([fortPolicy()]));assert.equal(r.format,'FortiOS REST API JSON');assert.equal(r.counts.high,1);assert.equal(r.policies[0].scope,'root');assert.equal(r.policies[0].logging,'off');});
test('Fortinet JSON: related object files selected first resolve groups',()=>{const a={vdom:'root',path:'firewall',name:'address',results:[{name:'Universe',subnet:'0.0.0.0 0.0.0.0'}]};const p=fortPolicy();p.srcaddr=[{name:'Universe'}];assert.equal(inspect([JSON.stringify(a),fortJSON([p])]).counts.high,1);});
test('Fortinet JSON: VDOM isolation preserved',()=>{const a=JSON.parse(fortJSON([fortPolicy()])),b={...a,vdom:'B'};const r=inspect(JSON.stringify({responses:[a,b]}));assert.equal(r.counts.rules,2);assert.equal(r.counts.scopes,2);assert.ok(!codes(r).includes('potentialRedundancy'));});
test('Fortinet JSON: omitted settings stay unknown',()=>{const p=fortPolicy();delete p.logtraffic;delete p['utm-status'];const r=inspect(fortJSON([p]));assert.equal(r.policies[0].logging,'unknown');assert.equal(r.policies[0].protection,'unknown');});
test('Fortinet JSON: pagination disables order inference',()=>{const r=inspect(fortJSON([fortPolicy(),fortPolicy(2)],{limit_reached:true}));assert.ok(r.warnings.some(w=>w.code==='apiPagination'));assert.ok(r.policies.every(p=>p.orderKnown===false));assert.ok(!codes(r).includes('potentialRedundancy'));});
test('Fortinet JSON: duplicate pages deduplicated, conflicts rejected',()=>{const s=fortJSON([fortPolicy()]);assert.equal(inspect([s,s]).counts.rules,1);const p=fortPolicy();p.action='deny';rejects([s,fortJSON([p])],'conflictingPages');});
test('Fortinet JSON: API failure and missing context rejected',()=>{rejects(fortJSON([],{status:'error'}),'apiFailure');rejects(fortJSON([fortPolicy()],{vdom:null}),'unsupportedFortinetJSON');});
test('Fortinet JSON: strings cannot inject CLI blocks',()=>{const p=fortPolicy();p.comments='hello\nnext\nend\nconfig system admin';assert.equal(inspect(fortJSON([p])).counts.rules,1);});
test('Fortinet JSON: raw arrays/FortiManager JSON unsupported',()=>{rejects(JSON.stringify([fortPolicy()]),'unsupportedFortinetJSON','fortinet');rejects('{"result":[{"data":[]}]}','unsupportedFortinetJSON','fortinet');});
test('PAN-OS CLI: selectors/profiles/context parsed',()=>{const r=inspect(paCLI('Lab rule','set rulebase security rules "Lab rule" profile-setting group Lab-Profile'));assert.equal(r.counts.high,1);assert.equal(r.policies[0].protection,'on');assert.equal(r.policies[0].scope,'vsys[vsys1]/rulebase');assert.ok(r.warnings.some(w=>w.code==='paloCLIContext'));});
test('PAN-OS CLI: repeated/bracket selectors preserve spaces',()=>{const s=paCLI().replace('source any','source [ "Client A" "Client B" ]')+'\nset rulebase security rules "Wide access" source "Client C"';assert.deepEqual(inspect(s).policies[0].src,['Client A','Client B','Client C']);});
test('PAN-OS CLI: Panorama scopes isolated',()=>{const s=paCLI().replaceAll('set rulebase','set device-group "DG A" pre-rulebase')+'\n'+paCLI().replaceAll('set rulebase','set device-group "DG B" post-rulebase');assert.equal(inspect(s).counts.scopes,2);});
test('PAN-OS CLI: negation/category/HIP suppress broad access',()=>{for(const x of ['negate-source yes','category finance','source-hip Finance-Laptops'])assert.equal(inspect(paCLI('R',`set rulebase security rules R ${x}`)).counts.high,0);});
test('PAN-OS CLI: missing selectors remain incomplete',()=>{const r=inspect(paCLI().replace('set rulebase security rules "Wide access" destination any',''));assert.equal(r.counts.high,0);assert.ok(r.warnings.some(w=>w.code==='incompleteRules'));});
test('PAN-OS CLI: malformed quotes/lists/change scripts rejected',()=>{rejects(paCLI()+'\nset rulebase security rules "R source any','malformedPaloCLI','paloalto');rejects(paCLI().replace('source any','source [ any'),'malformedPaloCLI');rejects(paCLI()+'\ndelete rulebase security rules "Wide access"','malformedPaloCLI');});
test('PAN-OS JSON: hierarchy profiles and canonical context',()=>{const e=paEntry();e['profile-setting']={profiles:{virus:{member:['Lab-AV']}}};const r=inspect(paJSON(e));assert.equal(r.counts.high,1);assert.equal(r.policies[0].protection,'on');assert.equal(r.policies[0].scope,'vsys[vsys1]/rulebase');});
test('PAN-OS JSON: keyed CLI hierarchy and XML API wrapper',()=>{const s=JSON.stringify({vsys:{vsys1:{rulebase:{security:{rules:{'Wide access':paEntry()}}}}}});assert.equal(inspect(s).counts.rules,1);const d=JSON.parse(paJSON(paEntry()));assert.equal(inspect(JSON.stringify({response:{result:d}})).counts.high,1);});
test('PAN-OS REST JSON: order/profiles unknown and pagination flagged',()=>{const r=inspect(JSON.stringify({'@status':'success',result:{'@total-count':'2',entry:[paEntry()]}}));assert.equal(r.counts.high,1);assert.equal(r.policies[0].orderKnown,false);assert.equal(r.policies[0].protection,'unknown');assert.ok(r.warnings.some(w=>w.code==='apiPagination'));});
test('PAN-OS REST JSON: Panorama needs explicit endpoint',()=>{const e={...paEntry(),'@location':'device-group','@device-group':'DG A'};const d={result:{entry:[e]}};rejects(JSON.stringify(d),'missingPaloContext');d.resource='Policies/SecurityPreRules';assert.equal(inspect(JSON.stringify(d)).policies[0].scope,'device-group[DG A]/pre-rulebase');});
test('PAN-OS JSON: XML injection escaped and invalid keys rejected',()=>{const e=paEntry('<img src=x onerror=alert(1)>');assert.equal(inspect(paJSON(e)).policies[0].name,e['@name']);e['x><script']=true;rejects(paJSON(e),'unsupportedPaloJSON');});
test('Snapshot: JSON/XML round-trip all vendors preserves normalized fields and findings',()=>{for(const v of ['fortinet','paloalto','checkpoint']){const m=core.parse(demo[v],v,XMLParser),j=core.parse(JSON.stringify(core.snapshot(m)),'auto',XMLParser),x=core.parse(core.snapshotXML(m),'auto',XMLParser);assert.deepEqual(core.snapshot(j).policies,core.snapshot(m).policies);assert.deepEqual(core.snapshot(x).policies,core.snapshot(m).policies);assert.deepEqual(codes(core.analyze(j)),codes(core.analyze(m)));assert.deepEqual(core.diff(m,x),{added:[],removed:[],changed:[]});}});
test('Snapshot: incomplete/unknown criteria survive reload',()=>{const m=core.parse(policy(1).replace('set dstaddr "all"','')),n=core.parse(JSON.stringify(core.snapshot(m)));assert.equal(n.rules[0].complete,false);assert.equal(n.rules[0].logging,'unknown');assert.equal(core.analyze(n).counts.high,0);});
test('Snapshot: version/vendor/types/duplicate IDs validated',()=>{const s=core.snapshot(core.parse(policy(1)));for(const mutate of [s=>s.schemaVersion=2,s=>s.vendor='unknown',s=>s.policies[0].enabled='false',s=>s.policies[0].logging='yes',s=>s.policies.push({...s.policies[0]}),s=>s.policies[0].src='any',s=>delete s.policies[0].orderKnown]){const d=structuredClone(s);mutate(d);rejects(JSON.stringify(d),'invalidSnapshot');}rejects(JSON.stringify(s),'vendorMismatch','paloalto');});
test('Snapshot XML: escaping/entities/invalid booleans/unrelated XML',()=>{const m=core.parse(policy(1,'set name "A & B <C>"'));assert.equal(core.parse(core.snapshotXML(m),'auto',XMLParser).rules[0].name,'A & B <C>');rejects(core.snapshotXML(m).replace('<enabled>true</enabled>','<enabled>yes</enabled>'),'invalidSnapshot');rejects('<!DOCTYPE x [<!ENTITY a "boom">]>'+core.snapshotXML(m),'unsafeXML');rejects('<hello/>','unknownFormat');});
test('Snapshot: unrelated passwords never included',()=>{const p=fortPolicy();p.password='DO_NOT_EXPORT_ME';const m=core.parse(fortJSON([p]));assert.ok(!JSON.stringify(core.snapshot(m)).includes('DO_NOT_EXPORT_ME'));assert.ok(!core.snapshotXML(m).includes('DO_NOT_EXPORT_ME'));});
test('Input: mixed vendors rejected; BOM accepted',()=>{rejects([fortJSON([fortPolicy()]),demo.checkpoint],'vendorMismatch');assert.equal(inspect('\uFEFF'+fortJSON([fortPolicy()])).counts.rules,1);});
test('Diff: Palo Alto UUID JSON and name-only CLI match',()=>{const e=paEntry();e['@uuid']='lab-uuid';const a=core.parse(paJSON(e),'paloalto',XMLParser),b=core.parse(paCLI(),'paloalto',XMLParser);assert.deepEqual(core.diff(a,b),{added:[],removed:[],changed:[]});});
test('Diff: API order uncertainty skips reordered verdict',()=>{const a=core.parse(paJSON(paEntry()),'auto',XMLParser),b=core.parse(JSON.stringify({result:{entry:[paEntry()]}}),'paloalto',XMLParser);b.rules[0].order=9;assert.ok(!core.diff(a,b).changed.flatMap(r=>r.changes).some(c=>c.field==='order'));});
test('Alternate native demos: Fortinet JSON and PAN-OS CLI/JSON work automatically',()=>{for(const key of ['fortinetJSON','paloaltoCLI','paloaltoJSON']){const r=inspect(demo[key]);assert.equal(r.counts.high,1);assert.equal(r.counts.rules,key==='fortinetJSON'?4:3);}});
test('Native format comparison: demo policy fields equivalent across formats',()=>{for(const [a,b] of [['fortinet','fortinetJSON'],['paloalto','paloaltoCLI'],['paloalto','paloaltoJSON']])assert.deepEqual(core.diff(core.parse(demo[a],'auto',XMLParser),core.parse(demo[b],'auto',XMLParser)),{added:[],removed:[],changed:[]});});
