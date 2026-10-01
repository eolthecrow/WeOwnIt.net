/* WeOwnIT Firewall Review: static, local, conservative policy analysis. No network or storage APIs. */
(function (root) {
  'use strict';
  const VERSION = '1.0.0';
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
    return Object.assign({id:'', name:'', scope:'', order:0, action:'unknown', enabled:true, src:[], dst:[], service:[], from:[ANY], to:[ANY], apps:[ANY], users:[ANY], schedule:'always', vpn:'any', logging:'unknown', protection:'unknown', comment:'', negated:false, complex:false, unresolved:[], complete:true}, data);
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
      const path=[]; for(let p=rb;p && p!==config;p=p.parentElement) path.unshift(p.localName+(p.getAttribute('name')?'['+p.getAttribute('name')+']':''));
      const scope=path.join('/');
      for (const e of children(rules,'entry')) {
        const profiles=child(e,'profile-setting');
        const hasProfiles=profiles && Array.from(profiles.getElementsByTagName('member')).some(n=>n.textContent.trim() && n.textContent.trim()!=='none');
        const start=txt(e,'log-start'), end=txt(e,'log-end');
        const src=clean(members(e,'source')),dst=clean(members(e,'destination')),service=clean(members(e,'service'));
        const from=clean(members(e,'from')),to=clean(members(e,'to')),apps=clean(members(e,'application'));
        add(m,rule({id:e.getAttribute('uuid')||e.getAttribute('name'),name:e.getAttribute('name')||'Unnamed',scope,src,dst,service,from,to,apps,action:txt(e,'action')||'unknown',enabled:txt(e,'disabled')!=='yes',logging:start==='yes'||end==='yes'?'on':start==='no'&&end==='no'?'off':'unknown',protection:hasProfiles?'on':'off',comment:txt(e,'description'),users:clean(members(e,'source-user').length?members(e,'source-user'):[ANY]),schedule:txt(e,'schedule')||'always',negated:txt(e,'negate-source')==='yes'||txt(e,'negate-destination')==='yes',complex:!!child(e,'hip-profiles')||!!child(e,'source-hip')||!!child(e,'destination-hip')||txt(e,'rule-type')==='intrazone',complete:src.length>0&&dst.length>0&&service.length>0&&from.length>0&&to.length>0&&apps.length>0}));
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
  function finish(m) {
    m.scopes=uniq(m.rules.map(r=>r.scope));
    if(m.rules.some(r=>!r.complete)) note(m,'incompleteRules');
    if(m.rules.some(r=>r.negated||r.complex)) note(m,'complexRules');
    return m;
  }
  function detect(text) {
    const s=text.trim(); if(s.startsWith('<') && /<(config|response)\b/.test(s)) return 'paloalto';
    if(/^[\s\S]*?config\s+(firewall policy|vdom)\b/m.test(s)) return 'fortinet';
    if((s.startsWith('{')||s.startsWith('[')) && /"rulebase"\s*:/.test(s)) return 'checkpoint';
    return null;
  }
  function parse(texts,vendor='auto',XMLParser) {
    const input=list(texts); if(!input.length || input.every(t=>!t.trim())) fail('empty');
    if(input.reduce((n,t)=>n+new TextEncoder().encode(t).length,0)>MAX_BYTES) fail('tooLarge');
    vendor=vendor==='auto'?input.map(detect).find(Boolean):vendor;
    if(!vendor) fail('unknownFormat');
    if(vendor!=='checkpoint' && input.length!==1) fail('oneFile');
    return vendor==='fortinet'?parseFortinet(input[0]):vendor==='paloalto'?parsePaloAlto(input[0],XMLParser):vendor==='checkpoint'?parseCheckPoint(input):fail('unknownFormat');
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
        const b=rs[j]; if(!b.complete || b.negated || b.complex || b.schedule==='unknown'||b.vpn==='unknown') continue;
        for(let i=0;i<j;i++) {
          const a=rs[i]; if(!a.complete||a.negated||a.complex||a.schedule!==b.schedule||a.vpn!==b.vpn||a.schedule==='unknown'||!['allow','accept','deny','drop','reject'].includes(a.action)) continue;
          if(['src','dst','service','from','to','apps','users'].every(k=>subset(a[k],b[k]))) {finding(a.action===b.action?'potentialRedundancy':'potentialConflict','medium',b,a);break;}
        }
      }
    }
    const order={high:0,medium:1,low:2};findings.sort((a,b)=>order[a.severity]-order[b.severity]);
    return {version:VERSION,vendor:m.vendor,format:m.format,counts:{rules:m.rules.length,active:m.rules.filter(r=>r.enabled).length,disabled:m.rules.filter(r=>!r.enabled).length,scopes:m.scopes.length,objects:m.objects,high:findings.filter(f=>f.severity==='high').length,medium:findings.filter(f=>f.severity==='medium').length,low:findings.filter(f=>f.severity==='low').length},findings,warnings:m.warnings,policies:m.rules};
  }
  function diff(before,after) {
    if(before.vendor!==after.vendor) fail('vendorMismatch');
    const key=r=>r.scope+'\u0000'+r.id;
    const old=new Map(before.rules.map(r=>[key(r),r])), now=new Map(after.rules.map(r=>[key(r),r]));
    const fields=['name','action','enabled','src','dst','service','from','to','apps','users','schedule','vpn','logging','protection','negated','complex','comment','order'];
    const added=[],removed=[],changed=[];
    for(const [k,r] of now) {if(!old.has(k)) added.push(r);else {const a=old.get(k), changes=fields.filter(f=>JSON.stringify(a[f])!==JSON.stringify(r[f])).map(field=>({field,before:a[field],after:r[field]}));if(changes.length) changed.push({id:r.id,name:r.name,scope:r.scope,changes});}}
    for(const [k,r] of old) if(!now.has(k)) removed.push(r);
    return {added,removed,changed};
  }
  const api={VERSION,MAX_BYTES,MAX_RULES,ANY,parse,analyze,diff,detect};
  root.FirewallReview=api;if(typeof module==='object' && module.exports) module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:this);
