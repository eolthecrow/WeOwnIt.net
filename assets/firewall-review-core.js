/* WeOwnIT Firewall Review: static, local, conservative policy analysis. No network or storage APIs. */
(function (root) {
  'use strict';
  const VERSION = '1.1.0';
  const SCHEMA = 'weownit.firewall-review.snapshot';
  const MAX_BYTES = 5 * 1024 * 1024, MAX_RULES = 5000, PAIR_LIMIT = 350;
  const ANY = '__ANY__';
  const fail = (code) => { const e = new Error(code); e.code = code; throw e; };
  const list = value => value == null ? [] : Array.isArray(value) ? value : [value];
  const uniq = values => [...new Set(values)].sort();
  const isAny = value => value === ANY;
  const clean = values => uniq(list(values).map(String).filter(Boolean));
  const cliAny = values => clean(values.map(v => v === 'any' ? ANY : v));
  const all = values => values.includes(ANY);
  const note = (model, code, detail = '') => { if (!model.warnings.some(w => w.code === code && w.detail === detail)) model.warnings.push({code, detail}); };
  function model(vendor) { return {version: VERSION, vendor, rules: [], warnings: [], scopes: [], format: '', objects: 0}; }
  function rule(data) {
    return Object.assign({id:'', name:'', scope:'', order:0, orderKnown:true, action:'unknown', enabled:true, src:[], dst:[], service:[], from:[ANY], to:[ANY], apps:[ANY], users:[ANY], schedule:'always', vpn:'any', logging:'unknown', protection:'unknown', comment:'', negated:false, complex:false, unresolved:[], complete:true}, data);
  }
  function add(model, entry) {
    if (model.rules.length >= MAX_RULES) fail('tooManyRules');
    entry.order = model.rules.filter(r => r.scope === entry.scope).length + 1;
    if (!entry.src.length || !entry.dst.length || !entry.service.length) entry.complete = false;
    model.rules.push(entry);
  }
  // CLI tokenization preserves spaces and escaped quotes; never evaluates input.
  function tokens(line) {
    const out = []; const re = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^\s]+)/g;
    let m; while ((m = re.exec(line))) out.push((m[1] ?? m[2] ?? m[3]).replace(/\\(["'\\])/g, '$1'));
    return out;
  }
  function parseFortinet(text) {
    const m = model('fortinet'); m.format = 'FortiOS CLI';
    const base = {kind:'root', children:[], props:Object.create(null)}; const stack = [base];
    let incomplete = false;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim(); if (!line || line.startsWith('#')) continue;
      const t = tokens(line), cmd = t.shift(), parent = stack[stack.length - 1];
      if (cmd === 'config' || cmd === 'edit') {
        const n = {kind:cmd, name:t.join(' '), line:0, children:[], props:Object.create(null)};
        parent.children.push(n); stack.push(n);
      } else if (cmd === 'next' || cmd === 'end') {
        const expected = cmd === 'next' ? 'edit' : 'config';
        if (stack.length < 2 || parent.kind !== expected) { incomplete = true; continue; }
        stack.pop();
      } else if (['set','unset','append'].includes(cmd)) {
        const key = t.shift(); if (!key) continue;
        parent.props[key] = cmd === 'unset' ? [] : cmd === 'append' ? [...(parent.props[key] || []), ...t] : t;
      }
    }
    if (stack.length !== 1 || incomplete) fail('malformedCLI');
    const scopes = new Map();
    function walk(n, scope='root') {
      if (n.kind === 'edit' && n.vdom) scope = n.name;
      if (n.kind === 'edit' && n.managerContext) {scope += '/'+n.managerContext+':'+n.name;note(m,'managerScope');}
      if (n.kind === 'config' && n.name === 'vdom') for (const child of n.children) child.vdom = true;
      if (n.kind === 'config' && ['adom','pkg'].includes(n.name)) for (const child of n.children) child.managerContext = n.name;
      if (n.kind === 'config' && ['firewall policy','firewall address','firewall addrgrp','firewall service custom','firewall service group'].includes(n.name)) {
        if (!scopes.has(scope)) scopes.set(scope, []); scopes.get(scope).push(n);
      }
      n.children.forEach(c => walk(c, scope));
    }
    walk(base);
    for (const [scope, configs] of scopes) {
      const addresses = new Map(), services = new Map();
      for (const c of configs) for (const e of c.children.filter(x => x.kind === 'edit')) {
        if (c.name === 'firewall address') {
          const subnet=e.props.subnet;
          addresses.set(e.name, {any:!!subnet && subnet.join(' ') === '0.0.0.0 0.0.0.0'});
        }
        if (c.name === 'firewall addrgrp') addresses.set(e.name, {members:e.props.member || []});
        if (c.name === 'firewall service custom') services.set(e.name, {any:e.props.protocol?.[0] === 'IP' && (!e.props['protocol-number'] || e.props['protocol-number'][0] === '0')});
        if (c.name === 'firewall service group') services.set(e.name, {members:e.props.member || []});
      }
      m.objects += addresses.size + services.size;
      function expand(names, map, seen = new Set()) {
        const result=[];
        for (const name of names) {
          if ((map===addresses && name==='all') || (map===services && name==='ALL')) {result.push(ANY); continue;}
          const obj=map.get(name);
          if (obj?.any) {result.push(ANY); continue;}
          if (obj?.members?.length && !seen.has(name) && seen.size < 30) {
            result.push(...expand(obj.members, map, new Set([...seen, name])));
          } else result.push(name);
        }
        return clean(result);
      }
      for (const c of configs.filter(x=>x.name==='firewall policy')) for (const e of c.children.filter(x=>x.kind==='edit')) {
        const p=e.props, get=k=>(p[k] || []).join(' ');
        const src=expand(p.srcaddr || [], addresses), dst=expand(p.dstaddr || [], addresses), service=expand(p.service || [], services);
        const log=get('logtraffic'), utm=get('utm-status');
        add(m, rule({id:e.name,name:get('name') || 'Policy '+e.name,scope,src,dst,service,from:cliAny(p.srcintf || []),to:cliAny(p.dstintf || []),action:get('action') || 'deny',enabled:get('status') !== 'disable',logging:log==='disable'?'off':['all','utm'].includes(log)?'on':'unknown',protection:utm==='disable'?'off':utm==='enable'?'on':'unknown',comment:get('comments'),schedule:get('schedule') || 'unknown',users:clean(p.users || p.groups || [ANY]),negated:['srcaddr-negate','dstaddr-negate','service-negate'].some(k=>get(k)==='enable'),complex:['internet-service','internet-service-src','identity-based','match-vip-only'].some(k=>get(k)==='enable') || !!p['application-list'],complete:src.length>0 && dst.length>0 && service.length>0 && !!p.srcintf && !!p.dstintf}));
      }
    }
    if (!m.rules.length) fail('noFortinetRules');
    note(m,'fortinetDefaults'); note(m,'staticScope');
    return finish(m);
  }
  const children = (node, name) => Array.from(node?.children || []).filter(n=>n.localName===name);
  const child = (node, name) => children(node,name)[0];
  const txt = (node, name) => child(node,name)?.textContent.trim() || '';
  const members = (node,name) => children(child(node,name),'member').map(n=>n.textContent.trim()).map(v=>v==='any'?ANY:v);
  function parsePaloAlto(text, XMLParser) {
    if (/<!DOCTYPE|<!ENTITY/i.test(text)) fail('unsafeXML');
    const Parser=XMLParser || root.DOMParser; if (!Parser) fail('xmlUnavailable');
    const doc=new Parser().parseFromString(text,'application/xml');
    if (doc.getElementsByTagName('parsererror').length) fail('malformedXML');
    const m=model('paloalto'); m.format='PAN-OS XML';
    const config=doc.documentElement.localName==='config'?doc.documentElement:doc.getElementsByTagName('config')[0];
    if (!config) fail('noPaloRules');
    // Treat each actual rulebase as a separate snapshot. Do not invent Panorama inheritance.
    for (const security of Array.from(config.getElementsByTagName('security'))) {
      const rb=security.parentElement; if (!['rulebase','pre-rulebase','post-rulebase'].includes(rb?.localName)) continue;
      const rules=child(security,'rules'); if (!rules) continue;
      const path=[]; for(let p=rb;p && p!==config;p=p.parentElement) {
        if(p.localName==='entry'&&['vsys','device-group'].includes(p.parentElement?.localName))path.unshift(p.parentElement.localName+'['+p.getAttribute('name')+']');
        else if(!['vsys','device-group'].includes(p.localName))path.unshift(p.localName+(p.getAttribute('name')?'['+p.getAttribute('name')+']':''));
      }
      const context=path.findIndex(p=>/^(vsys|device-group|shared)(\[|$)/.test(p));
      const scope=(context>=0?path.slice(context):['vsys[vsys1]',...path]).join('/');
      for (const e of children(rules,'entry')) {
        const profiles=child(e,'profile-setting');
        const hasProfiles=profiles && Array.from(profiles.getElementsByTagName('member')).some(n=>n.textContent.trim() && n.textContent.trim()!=='none');
        const start=txt(e,'log-start'), end=txt(e,'log-end');
        const src=clean(members(e,'source')),dst=clean(members(e,'destination')),service=clean(members(e,'service'));
        const from=clean(members(e,'from')),to=clean(members(e,'to')),apps=clean(members(e,'application'));
        const restricted=k=>{const values=members(e,k);return values.length>0&&!values.includes(ANY);};
        add(m,rule({id:e.getAttribute('uuid')||e.getAttribute('name'),name:e.getAttribute('name')||'Unnamed',scope,src,dst,service,from,to,apps,action:txt(e,'action')||'unknown',enabled:txt(e,'disabled')!=='yes',logging:start==='yes'||end==='yes'?'on':start==='no'&&end==='no'?'off':'unknown',protection:hasProfiles?'on':'off',comment:txt(e,'description'),users:clean(members(e,'source-user').length?members(e,'source-user'):[ANY]),schedule:txt(e,'schedule')||'always',negated:txt(e,'negate-source')==='yes'||txt(e,'negate-destination')==='yes',complex:['hip-profiles','source-hip','destination-hip','category'].some(restricted)||!!child(child(e,'target'),'devices')||txt(e,'rule-type')==='intrazone',complete:src.length>0&&dst.length>0&&service.length>0&&from.length>0&&to.length>0&&apps.length>0}));
      }
    }
    m.objects=Array.from(config.getElementsByTagName('address')).reduce((n,e)=>n+children(e,'entry').length,0);
    if (!m.rules.length) fail('noPaloRules');
    note(m,'paloDefaults'); note(m,'panoramaScope'); note(m,'staticScope');
    return finish(m);
  }
  function parseCheckPoint(texts) {
    const m=model('checkpoint'); m.format='Check Point Management API JSON';
    const documents=list(texts).map(text=>{try{return JSON.parse(text);}catch(_){fail('malformedJSON');}});
    const objects=new Map(), rulebases=[], visited=new Set(); let nodes=0;
    function collect(n, scope='Access layer', depth=0) {
      if(depth>35 || ++nodes>200000) fail('tooComplex');
      if(!n || typeof n!=='object') return;
      if(Array.isArray(n)) {n.forEach(x=>collect(x,scope,depth+1));return;}
      if(n.uid && n.type && n.type!=='access-rule' && n.type!=='access-section') objects.set(n.uid,n);
      if(Array.isArray(n.rulebase)) {
        if(n.type!=='access-section') rulebases.push({value:n,scope:n.uid || n.name || scope});
        else { /* Sections are flattened with their parent, not new layers. */ }
      }
      for(const [key,value] of Object.entries(n)) if(value && typeof value==='object') collect(value,scope,depth+1);
    }
    documents.forEach(x=>collect(x)); m.objects=objects.size;
    function ref(value, seen=new Set(), depth=0) {
      if(depth>25) return {values:[String(value)],unknown:true};
      if(typeof value==='string') {
        if(value===ANY || value==='Any') return {values:[ANY],unknown:false};
        const obj=objects.get(value);
        if(obj && !seen.has(value)) return ref(obj,new Set([...seen,value]),depth+1);
        return {values:[value],unknown:/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(value)};
      }
      if(value && typeof value==='object') {
        if(value.type==='CpmiAnyObject') return {values:[ANY],unknown:false};
        if((value.type==='group'||value.type==='service-group') && value.members?.length) {
          const subs=value.members.map(v=>ref(v,seen,depth+1));return {values:uniq(subs.flatMap(v=>v.values)),unknown:subs.some(v=>v.unknown)};
        }
        return {values:[value.name || value.uid || 'Unknown'],unknown:!value.name};
      }
      return {values:[],unknown:true};
    }
    const resolve=values=>{const r=list(values).map(v=>ref(v));return {values:clean(r.flatMap(x=>x.values)),unknown:r.some(x=>x.unknown)};};
    function flatten(items,scope) {
      for(const r of items) {
        if(r.type==='access-section' && Array.isArray(r.rulebase)) {flatten(r.rulebase,scope);continue;}
        if(r.type!=='access-rule' || visited.has(scope+':'+r.uid)) continue;
        if(r.uid) visited.add(scope+':'+r.uid);
        const source=resolve(r.source), destination=resolve(r.destination), service=resolve(r.service), action=resolve(r.action), track=resolve(r.track?.type ?? r.track);
        const actionName=(action.values[0]||'unknown').toLowerCase(), trackName=(track.values[0]||'unknown').toLowerCase();
        const time=resolve(r.time),vpn=resolve(r.vpn);
        const unresolved=[]; for(const [k,v] of Object.entries({source,destination,service,action,track})) if(v.unknown) unresolved.push(k);
        add(m,rule({id:r.uid || String(r['rule-number']||m.rules.length+1),name:r.name || 'Rule '+(r['rule-number']||m.rules.length+1),scope,exportOrder:Number(r['rule-number'])||null,action:actionName==='accept'?'accept':['drop','reject'].includes(actionName)?'deny':actionName,src:source.values,dst:destination.values,service:service.values,enabled:r.enabled!==false,logging:trackName==='none'?'off':['log','account','extended log','detailed log','alert'].includes(trackName)?'on':'unknown',comment:r.comments || '',schedule:time.values.length?time.values.join('|'):'unknown',vpn:vpn.values.length?vpn.values.join('|'):'unknown',negated:r['source-negate']===true||r['destination-negate']===true||r['service-negate']===true,complex:!!r['inline-layer']||!!r['content-negate']||r['user-check']!=null,unresolved,complete:!source.unknown&&!destination.unknown&&!service.unknown&&!action.unknown&&source.values.length>0&&destination.values.length>0&&service.values.length>0}));
      }
    }
    rulebases.forEach(rb=>flatten(rb.value.rulebase,String(rb.scope)));
    for(const scope of uniq(rulebases.map(rb=>String(rb.scope)))) {
      const total=Math.max(...rulebases.filter(rb=>String(rb.scope)===scope).map(rb=>Number(rb.value.total)||0));
      if(total>m.rules.filter(r=>r.scope===scope).length) note(m,'pagination',String(total));
    }
    m.rules.sort((a,b)=>a.scope.localeCompare(b.scope)||(a.exportOrder??a.order)-(b.exportOrder??b.order));
    const orderByScope=new Map();for(const r of m.rules){r.order=(orderByScope.get(r.scope)||0)+1;orderByScope.set(r.scope,r.order);}
    if(!m.rules.length) fail('noCheckPointRules');
    if(m.rules.some(r=>r.unresolved.length)) note(m,'unresolvedObjects');
    note(m,'checkpointScope'); note(m,'staticScope');
    return finish(m);
  }
  // JSON/XML snapshots are a versioned review schema, never a vendor restore file.
  const scalarFields=['id','name','scope','action','schedule','vpn','logging','protection','comment'];
  const selectorFields=['src','dst','service','from','to','apps','users','unresolved'];
  const booleanFields=['enabled','negated','complex','complete','orderKnown'];
  const xmlEscape=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[c]));
  const plain=o=>!!o && typeof o==='object' && !Array.isArray(o);
  function jsonRead(text) {
    let data;try{data=JSON.parse(text);}catch(_){fail('malformedJSON');}
    let count=0;
    function bound(n,d=0){if(d>40||++count>200000)fail('tooComplex');if(n&&typeof n==='object')for(const v of Object.values(n))bound(v,d+1);}
    bound(data);return data;
  }
  function snapshot(m) {
    return {schema:SCHEMA,schemaVersion:1,vendor:m.vendor,sourceFormat:m.sourceFormat||m.format,objects:m.objects,
      warnings:m.warnings.map(w=>({code:w.code,detail:w.detail||''})),
      policies:m.rules.map(r=>Object.fromEntries([...scalarFields,...selectorFields,...booleanFields,'order'].map(k=>[k,r[k]])))};
  }
  function snapshotXML(m) {
    const s=snapshot(m);
    return '<?xml version="1.0" encoding="UTF-8"?>\n<firewall-review-snapshot schema="'+SCHEMA+'" schema-version="1" vendor="'+s.vendor+'">\n'+
      '<source-format>'+xmlEscape(s.sourceFormat)+'</source-format><objects>'+s.objects+'</objects>\n<warnings>'+s.warnings.map(w=>'<warning code="'+xmlEscape(w.code)+'">'+xmlEscape(w.detail)+'</warning>').join('')+'</warnings>\n<policies>'+s.policies.map(r=>'<policy>'+scalarFields.map(k=>'<'+k+'>'+xmlEscape(r[k])+'</'+k+'>').join('')+selectorFields.map(k=>'<'+k+'>'+r[k].map(v=>'<value>'+xmlEscape(v)+'</value>').join('')+'</'+k+'>').join('')+booleanFields.map(k=>'<'+k+'>'+r[k]+'</'+k+'>').join('')+'<order>'+r.order+'</order></policy>').join('\n')+'</policies>\n</firewall-review-snapshot>';
  }
  function snapshotModel(data,expectedVendor) {
    if(!plain(data)||data.schema!==SCHEMA||data.schemaVersion!==1||!['fortinet','paloalto','checkpoint'].includes(data.vendor))fail('invalidSnapshot');
    if(expectedVendor!=='auto'&&expectedVendor!==data.vendor)fail('vendorMismatch');
    if(!Array.isArray(data.policies)||!data.policies.length)fail('invalidSnapshot');
    if(data.policies.length>MAX_RULES)fail('tooManyRules');
    if(typeof data.sourceFormat!=='string'||!Number.isSafeInteger(data.objects)||data.objects<0||!Array.isArray(data.warnings))fail('invalidSnapshot');
    const m=model(data.vendor);m.sourceFormat=data.sourceFormat;m.objects=data.objects;
    const seen=new Set(),orders=new Map();
    for(const p of data.policies) {
      if(!plain(p)||scalarFields.some(k=>typeof p[k]!=='string')||selectorFields.some(k=>!Array.isArray(p[k])||p[k].some(v=>typeof v!=='string'))||booleanFields.some(k=>typeof p[k]!=='boolean')||!p.id||!p.scope||!Number.isSafeInteger(p.order)||p.order<1)fail('invalidSnapshot');
      if(!['on','off','unknown'].includes(p.logging)||!['on','off','unknown'].includes(p.protection))fail('invalidSnapshot');
      const key=p.scope+'\u0000'+p.id;if(seen.has(key))fail('invalidSnapshot');seen.add(key);
      if(p.order!==(orders.get(p.scope)||0)+1)fail('invalidSnapshot');orders.set(p.scope,p.order);
      const r=rule(Object.fromEntries([...scalarFields,...selectorFields,...booleanFields,'order'].map(k=>[k,Array.isArray(p[k])?clean(p[k]):p[k]])));
      if(!r.src.length||!r.dst.length||!r.service.length||!r.from.length||!r.to.length||!r.apps.length||r.unresolved.length)r.complete=false;
      m.rules.push(r);
    }
    for(const w of data.warnings){if(!plain(w)||typeof w.code!=='string'||typeof w.detail!=='string')fail('invalidSnapshot');note(m,w.code,w.detail);}
    note(m,'reviewSnapshot');note(m,'staticScope');return finish(m);
  }
  function parseSnapshotXML(text,expectedVendor,XMLParser) {
    if(/<!DOCTYPE|<!ENTITY/i.test(text))fail('unsafeXML');
    const Parser=XMLParser||root.DOMParser;if(!Parser)fail('xmlUnavailable');
    const doc=new Parser().parseFromString(text,'application/xml');if(doc.getElementsByTagName('parsererror').length)fail('malformedXML');
    const e=doc.documentElement;if(e.localName!=='firewall-review-snapshot')fail('invalidSnapshot');
    const data={schema:e.getAttribute('schema'),schemaVersion:Number(e.getAttribute('schema-version')),vendor:e.getAttribute('vendor'),sourceFormat:txt(e,'source-format'),objects:Number(txt(e,'objects')),warnings:children(child(e,'warnings'),'warning').map(w=>({code:w.getAttribute('code'),detail:w.textContent})),policies:[]};
    for(const p of children(child(e,'policies'),'policy')) {
      const r={};for(const k of scalarFields){if(children(p,k).length!==1)fail('invalidSnapshot');r[k]=child(p,k).textContent;}
      for(const k of selectorFields){if(children(p,k).length!==1)fail('invalidSnapshot');r[k]=children(child(p,k),'value').map(v=>v.textContent);}
      for(const k of booleanFields){const value=txt(p,k);if(children(p,k).length!==1||!['true','false'].includes(value))fail('invalidSnapshot');r[k]=value==='true';}
      r.order=Number(txt(p,'order'));data.policies.push(r);
    }
    const m=snapshotModel(data,expectedVendor);m.format='WeOwnIT review snapshot XML';return m;
  }
  function fortResponses(data) {return Array.isArray(data)?data:plain(data)&&Array.isArray(data.responses)?data.responses:[data];}
  function parseFortinetJSON(texts) {
    const responses=texts.flatMap(t=>fortResponses(jsonRead(t))),scopes=new Map(),warnings=[];
    const types={'firewall/policy':'firewall policy','firewall/address':'firewall address','firewall/addrgrp':'firewall addrgrp','firewall.service/custom':'firewall service custom','firewall.service/group':'firewall service group'};
    const fields=new Set(['name','srcintf','dstintf','srcaddr','dstaddr','service','action','status','logtraffic','utm-status','comments','schedule','users','groups','srcaddr-negate','dstaddr-negate','service-negate','internet-service','internet-service-src','identity-based','match-vip-only','application-list','subnet','member','protocol','protocol-number']);
    const quoted=v=>JSON.stringify(String(v));
    function values(key,value) {
      if(Array.isArray(value))return value.map(v=>plain(v)?v.name:typeof v==='string'||typeof v==='number'?v:null).filter(v=>v!=null).map(String);
      if(typeof value==='string')return key==='subnet'?value.trim().split(/\s+/):[value];
      return typeof value==='number'?[String(value)]:[];
    }
    let policyResponses=0;
    for(const r of responses) {
      if(!plain(r)||!types[r.path+'/'+r.name]||!Array.isArray(r.results)||typeof r.vdom!=='string'||!r.vdom)fail('unsupportedFortinetJSON');
      if((r.status&&r.status!=='success')||(r.http_status&&Number(r.http_status)!==200))fail('apiFailure');
      const kind=types[r.path+'/'+r.name],scope=r.vdom;
      if(!scopes.has(scope))scopes.set(scope,new Map());const configs=scopes.get(scope);
      if(!configs.has(kind))configs.set(kind,new Map());const entries=configs.get(kind);
      if(kind==='firewall policy')policyResponses++;
      if(r.limit_reached===true||r.limit_reached==='true')warnings.push('apiPagination');
      for(const p of r.results) {
        if(!plain(p))fail('unsupportedFortinetJSON');
        const id=kind==='firewall policy'?p.policyid:p.name;if(typeof id!=='string'&&typeof id!=='number')fail('unsupportedFortinetJSON');
        if(entries.has(String(id))) {if(JSON.stringify(entries.get(String(id)))!==JSON.stringify(p))fail('conflictingPages');continue;}
        entries.set(String(id),p);
      }
    }
    if(!policyResponses)fail('noFortinetRules');
    const lines=[];
    for(const [scope,configs] of scopes){lines.push('config vdom','edit '+quoted(scope));
      for(const [kind,entries] of configs){lines.push('config '+kind);
        for(const [id,p] of entries){lines.push('edit '+quoted(id));for(const [k,v] of Object.entries(p))if(fields.has(k)){const vals=values(k,v);if(vals.length)lines.push('set '+k+' '+vals.map(quoted).join(' '));}lines.push('next');}lines.push('end');}
      lines.push('next','end');
    }
    const m=parseFortinet(lines.join('\n'));m.format='FortiOS REST API JSON';
    // API array order is not treated as proof of effective rule evaluation order.
    m.rules.forEach(r=>r.orderKnown=false);note(m,'apiOrder');
    warnings.forEach(w=>note(m,w));note(m,'apiSnapshot');return m;
  }
  const panContainers=new Set(['devices','vsys','device-group','rules','address']);
  function panXML(key,value,depth=0) {
    if(depth>35)fail('tooComplex');if(!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key))fail('unsupportedPaloJSON');
    if(Array.isArray(value))return value.map(v=>panXML(key,v,depth+1)).join('');
    if(value==null)return '<'+key+'/>';
    if(!plain(value))return '<'+key+'>'+xmlEscape(value)+'</'+key+'>';
    let attrs='',body='';
    for(const [k,v] of Object.entries(value)) {
      if(k.startsWith('@')){if(!/^@[A-Za-z_][A-Za-z0-9_.-]*$/.test(k)||typeof v==='object')fail('unsupportedPaloJSON');attrs+=' '+k.slice(1)+'="'+xmlEscape(v)+'"';}
      else if(k==='#text'){if(typeof v==='object')fail('unsupportedPaloJSON');body+=xmlEscape(v);}
      else if(panContainers.has(key)&&k!=='entry'){body+=panXML('entry',{'@name':k,...v},depth+1);}
      else body+=panXML(k,v,depth+1);
    }
    return '<'+key+attrs+'>'+body+'</'+key+'>';
  }
  function parsePaloJSON(text,XMLParser) {
    const data=jsonRead(text);
    let config=data.config||data.response?.result?.config||data.result?.config;
    const hierarchy=!!config||['devices','vsys','device-group','shared','rulebase','pre-rulebase','post-rulebase'].some(k=>plain(data)&&k in data);
    if(hierarchy){config=config||data;const m=parsePaloAlto(panXML('config',config),XMLParser);m.format='PAN-OS configuration JSON';return m;}
    const result=data.result||data.response?.result||data;
    const entries=list(result?.entry);
    if(!entries.length||entries.some(e=>!plain(e)||!e['@name']||!e.source||!e.destination||!e.service))fail('unsupportedPaloJSON');
    if(data['@status']&&data['@status']!=='success')fail('apiFailure');
    const groups=new Map();
    for(const e of entries) {
      const location=e['@location'],name=location==='vsys'?e['@vsys']:location==='device-group'?e['@device-group']:location==='shared'?'shared':null;
      if(!name)fail('missingPaloContext');
      const resource=data.resource||data.endpoint||'';
      const rb=/SecurityPreRules/.test(resource)?'pre-rulebase':/SecurityPostRules/.test(resource)?'post-rulebase':location==='vsys'?'rulebase':null;
      if(!rb)fail('missingPaloContext');
      const key=JSON.stringify([location,name,rb]);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(e);
    }
    let body='';for(const [key,entries] of groups){const [location,name,rb]=JSON.parse(key),rules=panXML(rb,{security:{rules:{entry:entries}}});body+=location==='shared'?'<shared>'+rules+'</shared>':'<'+location+'><entry name="'+xmlEscape(name)+'">'+rules+'</entry></'+location+'>';}
    const m=parsePaloAlto('<config>'+body+'</config>',XMLParser);m.format='PAN-OS REST API JSON';
    m.rules.forEach(r=>{r.orderKnown=false;if(r.protection==='off')r.protection='unknown';});
    if(Number(result['@total-count'])>entries.length)note(m,'apiPagination');note(m,'apiOrder');note(m,'apiSnapshot');return m;
  }
  // Parse a full PAN-OS set-format listing, not an executable change script.
  function panTokens(line) {
    const out=[];let i=0;
    while(i<line.length){if(/\s/.test(line[i])){i++;continue;}if(line[i]==='['||line[i]===']'){out.push(line[i++]);continue;}
      let value='';const quote=line[i]==='"'||line[i]==="'"?line[i++]:null;let closed=!quote;
      while(i<line.length){const c=line[i];if(quote&&c===quote){i++;closed=true;break;}if(!quote&&(/[\s\[\]]/.test(c)))break;if(c==='\\'&&i+1<line.length&&(line[i+1]===quote||line[i+1]==='\\')){value+=line[i+1];i+=2;}else{value+=c;i++;}}
      if(!closed)fail('malformedPaloCLI');out.push(value);
    }return out;
  }
  function parsePaloCLI(text,XMLParser) {
    const contexts=new Map();let assumed=false,found=false;
    const lists=new Set(['from','to','source','destination','service','application','source-user','category','hip-profiles','source-hip','destination-hip']);
    for(const raw of text.split(/\r?\n/)){const line=raw.trim();if(!line||line.startsWith('#'))continue;
      const t=panTokens(line),cmd=t.shift(),rbIndex=t.findIndex(v=>['rulebase','pre-rulebase','post-rulebase'].includes(v));
      if(rbIndex<0||t[rbIndex+1]!=='security'||t[rbIndex+2]!=='rules')continue;
      if(cmd!=='set')fail('malformedPaloCLI');found=true;
      const prefix=t.slice(0,rbIndex),rb=t[rbIndex],name=t[rbIndex+3],tail=t.slice(rbIndex+4);if(!name||!tail.length)fail('malformedPaloCLI');
      const vi=prefix.indexOf('vsys'),di=prefix.indexOf('device-group'),si=prefix.indexOf('shared');
      let location,context;if(vi>=0){location='vsys';context=prefix[vi+1];}else if(di>=0){location='device-group';context=prefix[di+1];}else if(si>=0){location='shared';context='shared';}else if(!prefix.length){location='vsys';context='vsys1';assumed=true;}else fail('malformedPaloCLI');
      if(!context)fail('malformedPaloCLI');const key=JSON.stringify([location,context,rb]);if(!contexts.has(key))contexts.set(key,new Map());const rs=contexts.get(key);
      if(!rs.has(name))rs.set(name,{'@name':name});const r=rs.get(name),field=tail.shift();
      function value(ts){if(ts[0]==='['){if(ts.at(-1)!==']'||ts.slice(1,-1).some(v=>v==='['||v===']'))fail('malformedPaloCLI');return ts.slice(1,-1);}if(ts.includes('[')||ts.includes(']'))fail('malformedPaloCLI');return ts;}
      if(lists.has(field)){const vals=value(tail);if(!vals.length)fail('malformedPaloCLI');r[field]={member:clean([...(r[field]?.member||[]),...vals])};}
      else if(field==='profile-setting'){
        const sub=tail.shift();r[field]??={};if(sub==='group'){const vals=value(tail);if(!vals.length)fail('malformedPaloCLI');r[field].group={member:vals};}
        else if(sub==='profiles'){const kind=tail.shift(),vals=value(tail);if(!kind||!vals.length)fail('malformedPaloCLI');r[field].profiles??={};r[field].profiles[kind]={member:vals};}else fail('malformedPaloCLI');
      }else if(field==='target'){r.target={devices:{entry:{'@name':'unsupported-target'}}};}
      else {const vals=value(tail);if(vals.length!==1)fail('malformedPaloCLI');r[field]=vals[0];}
    }
    if(!found)fail('noPaloRules');let body='';for(const [key,rs] of contexts){const [location,name,rb]=JSON.parse(key),rules=panXML(rb,{security:{rules:{entry:[...rs.values()]}}});body+=location==='shared'?'<shared>'+rules+'</shared>':'<'+location+'><entry name="'+xmlEscape(name)+'">'+rules+'</entry></'+location+'>';}
    const m=parsePaloAlto('<config>'+body+'</config>',XMLParser);m.format='PAN-OS CLI set';if(assumed)note(m,'paloCLIContext');note(m,'paloCLIExport');return m;
  }

  function finish(m) {
    m.scopes=uniq(m.rules.map(r=>r.scope));
    if(m.rules.some(r=>!r.complete)) note(m,'incompleteRules');
    if(m.rules.some(r=>r.negated||r.complex)) note(m,'complexRules');
    return m;
  }
  function detect(text) {
    const s=text.trim(); if(/<firewall-review-snapshot\b/.test(s)||/"schema"\s*:\s*"weownit\.firewall-review\.snapshot"/.test(s))return 'snapshot';
    if(s.startsWith('<') && /<(config|response)\b/.test(s)) return 'paloalto';
    if(/^[\s\S]*?config\s+(firewall policy|vdom)\b/m.test(s)) return 'fortinet';
    if(/^set\s+.*\b(?:rulebase|pre-rulebase|post-rulebase)\s+security\s+rules\b/m.test(s))return 'paloalto';
    if((s.startsWith('{')||s.startsWith('['))&&/"path"\s*:\s*"firewall(?:\.service)?"/.test(s)&&/"results"\s*:/.test(s))return 'fortinet';
    if((s.startsWith('{')||s.startsWith('['))&&(/"(?:rulebase|pre-rulebase|post-rulebase)"\s*:\s*\{/.test(s)||/"@(?:vsys|device-group)"\s*:/.test(s)))return 'paloalto';
    if((s.startsWith('{')||s.startsWith('[')) && /"rulebase"\s*:/.test(s)) return 'checkpoint';
    return null;
  }
  function parse(texts,vendor='auto',XMLParser) {
    const input=list(texts).map(t=>t.replace(/^\uFEFF/,'')); if(!input.length || input.every(t=>!t.trim())) fail('empty');
    if(input.reduce((n,t)=>n+new TextEncoder().encode(t).length,0)>MAX_BYTES) fail('tooLarge');
    const detected=input.map(detect);
    if(detected.includes('snapshot')) {
      if(input.length!==1)fail('oneFile');const text=input[0].trim();
      if(text.startsWith('<'))return parseSnapshotXML(text,vendor,XMLParser);
      const m=snapshotModel(jsonRead(text),vendor);m.format='WeOwnIT review snapshot JSON';return m;
    }
    vendor=vendor==='auto'?detected.find(Boolean):vendor;
    if(!vendor) fail('unknownFormat');
    if(detected.some(v=>v&&v!==vendor))fail('vendorMismatch');
    const json=input.every(t=>/^[\s]*[\[{]/.test(t));
    if(vendor!=='checkpoint' && !(vendor==='fortinet'&&json) && input.length!==1) fail('oneFile');
    return vendor==='fortinet'?(json?parseFortinetJSON(input):parseFortinet(input[0])):vendor==='paloalto'?(json?parsePaloJSON(input[0],XMLParser):input[0].trim().startsWith('<')?parsePaloAlto(input[0],XMLParser):parsePaloCLI(input[0],XMLParser)):vendor==='checkpoint'?parseCheckPoint(input):fail('unknownFormat');
  }
  const allowed = r => ['accept','allow'].includes(r.action);
  function analyze(m) {
    const findings=[];
    function finding(code,severity,r,related=null) {findings.push({code,severity,ruleId:r.id,ruleName:r.name,scope:r.scope,relatedId:related?.id || null,relatedName:related?.name || null,evidence:{source:r.src,destination:r.dst,service:r.service,from:r.from,to:r.to,application:r.apps,action:r.action,logging:r.logging,protection:r.protection}});}
    for(const r of m.rules) {
      if(!r.enabled) continue;
      if(allowed(r)) {
        if(!r.negated && !r.complex && r.complete) {
          const dimensions=[all(r.src),all(r.dst),all(r.service) && all(r.apps)];
          if(dimensions.every(Boolean)) finding('anyAny','high',r);
          else if(dimensions.filter(Boolean).length>=2) finding('broadAllow','medium',r);
          if(all(r.src) && r.service.some(s=>/^(ssh|rdp|ms-rdp|telnet|vnc|ftp)$/i.test(s))) finding('adminService','medium',r);
        }
        if(r.logging==='off') finding('noLogging','medium',r);
        if(r.protection==='off') finding('noProtection','medium',r);
      }
      if(!r.comment.trim()) finding('noDescription','low',r);
    }
    // Potential coverage only: literal selectors and exact scope; no reachability proof.
    const subset=(a,b)=>a.length>0 && b.length>0 && (all(a)||b.every(x=>a.includes(x)));
    for(const scope of m.scopes) {
      const rs=m.rules.filter(r=>r.scope===scope && r.enabled);
      if(rs.length>PAIR_LIMIT) {note(m,'pairLimit',scope);continue;}
      for(let j=1;j<rs.length;j++) {
        const b=rs[j]; if(!b.orderKnown || !b.complete || b.negated || b.complex || b.schedule==='unknown'||b.vpn==='unknown') continue;
        for(let i=0;i<j;i++) {
          const a=rs[i]; if(!a.orderKnown||!a.complete||a.negated||a.complex||a.schedule!==b.schedule||a.vpn!==b.vpn||a.schedule==='unknown'||!['allow','accept','deny','drop','reject'].includes(a.action)) continue;
          if(['src','dst','service','from','to','apps','users'].every(k=>subset(a[k],b[k]))) {finding(a.action===b.action?'potentialRedundancy':'potentialConflict','medium',b,a);break;}
        }
      }
    }
    const order={high:0,medium:1,low:2};findings.sort((a,b)=>order[a.severity]-order[b.severity]);
    return {version:VERSION,vendor:m.vendor,format:m.format,counts:{rules:m.rules.length,active:m.rules.filter(r=>r.enabled).length,disabled:m.rules.filter(r=>!r.enabled).length,scopes:m.scopes.length,objects:m.objects,high:findings.filter(f=>f.severity==='high').length,medium:findings.filter(f=>f.severity==='medium').length,low:findings.filter(f=>f.severity==='low').length},findings,warnings:m.warnings,policies:m.rules};
  }
  function diff(before,after) {
    if(before.vendor!==after.vendor) fail('vendorMismatch');
    const nameKey=r=>r.scope+'\u0000'+r.name;
    const afterIds=new Set(after.rules.map(r=>r.scope+'\u0000'+r.id));
    const commonIds=new Set(before.rules.filter(r=>afterIds.has(r.scope+'\u0000'+r.id)).map(r=>r.scope+'\u0000'+r.id));
    const duplicateNames=new Set();for(const rs of [before.rules,after.rules]){const seen=new Set();for(const r of rs){const n=nameKey(r);if(seen.has(n))duplicateNames.add(n);seen.add(n);}}
    const key=r=>r.scope+'\u0000'+(before.vendor==='paloalto'&&!commonIds.has(r.scope+'\u0000'+r.id)&&!duplicateNames.has(nameKey(r))?'name:'+r.name:'id:'+r.id);
    const old=new Map(before.rules.map(r=>[key(r),r])), now=new Map(after.rules.map(r=>[key(r),r]));
    const fields=['name','action','enabled','src','dst','service','from','to','apps','users','schedule','vpn','logging','protection','negated','complex','comment','order'];
    const added=[],removed=[],changed=[];
    for(const [k,r] of now) {if(!old.has(k)) added.push(r);else {const a=old.get(k), changes=fields.filter(f=>(f!=='order'||a.orderKnown&&r.orderKnown)&&JSON.stringify(a[f])!==JSON.stringify(r[f])).map(field=>({field,before:a[field],after:r[field]}));if(changes.length) changed.push({id:r.id,name:r.name,scope:r.scope,changes});}}
    for(const [k,r] of old) if(!now.has(k)) removed.push(r);
    return {added,removed,changed};
  }
  const api={VERSION,SCHEMA,MAX_BYTES,MAX_RULES,ANY,parse,analyze,diff,detect,snapshot,snapshotXML};
  root.FirewallReview=api;if(typeof module==='object' && module.exports) module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:this);
