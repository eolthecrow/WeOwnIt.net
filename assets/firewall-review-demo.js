/* Synthetic fixtures only. No customer configurations. */
window.FirewallReviewDemos = {
fortinet: `# Synthetic WeOwnIT lab — FortiOS CLI
config firewall address
    edit "Lab-Servers"
        set subnet 10.30.0.0 255.255.255.0
    next
end
config firewall policy
    edit 10
        set name "Guest-to-Servers"
        set srcintf "guest"
        set dstintf "servers"
        set srcaddr "all"
        set dstaddr "Lab-Servers"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic disable
        set utm-status disable
    next
    edit 20
        set name "Deny-Guest-SSH"
        set srcintf "guest"
        set dstintf "servers"
        set srcaddr "all"
        set dstaddr "Lab-Servers"
        set action deny
        set schedule "always"
        set service "SSH"
        set logtraffic all
        set comments "Intended restriction; check preceding rule"
    next
    edit 30
        set name "Temporary-wide-access"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set utm-status enable
    next
    edit 40
        set name "Disabled-lab-policy"
        set status disable
        set srcintf "guest"
        set dstintf "servers"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end`,
paloalto: `<?xml version="1.0"?>
<config version="11.1.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules>
<entry name="Guest-to-Servers" uuid="lab-pa-10"><from><member>guest</member></from><to><member>servers</member></to><source><member>any</member></source><destination><member>Lab-Servers</member></destination><source-user><member>any</member></source-user><application><member>any</member></application><service><member>any</member></service><action>allow</action><log-start>no</log-start><log-end>no</log-end></entry>
<entry name="Deny-Guest-SSH" uuid="lab-pa-20"><from><member>guest</member></from><to><member>servers</member></to><source><member>any</member></source><destination><member>Lab-Servers</member></destination><application><member>ssh</member></application><service><member>application-default</member></service><action>deny</action><log-start>no</log-start><log-end>yes</log-end><description>Review preceding broad allow</description></entry>
<entry name="Temporary-wide-access" uuid="lab-pa-30"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action><log-start>no</log-start><log-end>yes</log-end><profile-setting><group><member>Lab-Security-Profiles</member></group></profile-setting></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>`,
checkpoint: JSON.stringify({uid:"lab-access-layer",name:"Lab Network",from:1,to:3,total:3,"objects-dictionary":[{uid:"97aeb369-9aea-11d5-bd16-0090272ccb30",name:"Any",type:"CpmiAnyObject"},{uid:"6c488338-8eec-4103-ad21-cd461ac2c476",name:"Accept",type:"RulebaseAction"},{uid:"6c488338-8eec-4103-ad21-cd461ac2c477",name:"Drop",type:"RulebaseAction"},{uid:"6c488338-8eec-4103-ad21-cd461ac2c478",name:"None",type:"Track"},{uid:"6c488338-8eec-4103-ad21-cd461ac2c479",name:"Log",type:"Track"},{uid:"6c488338-8eec-4103-ad21-cd461ac2c480",name:"Lab-Servers",type:"network",subnet4:"10.30.0.0",'mask-length4':24},{uid:"6c488338-8eec-4103-ad21-cd461ac2c481",name:"SSH",type:"service-tcp",port:"22"}],rulebase:[{uid:"lab-cp-10",type:"access-rule","rule-number":1,name:"Broad-to-Servers",enabled:true,source:["97aeb369-9aea-11d5-bd16-0090272ccb30"],destination:["6c488338-8eec-4103-ad21-cd461ac2c480"],service:["97aeb369-9aea-11d5-bd16-0090272ccb30"],action:"6c488338-8eec-4103-ad21-cd461ac2c476",track:{type:"6c488338-8eec-4103-ad21-cd461ac2c478"},time:["97aeb369-9aea-11d5-bd16-0090272ccb30"],vpn:["97aeb369-9aea-11d5-bd16-0090272ccb30"]},{uid:"lab-cp-20",type:"access-rule","rule-number":2,name:"Deny-SSH",enabled:true,source:["97aeb369-9aea-11d5-bd16-0090272ccb30"],destination:["6c488338-8eec-4103-ad21-cd461ac2c480"],service:["6c488338-8eec-4103-ad21-cd461ac2c481"],action:"6c488338-8eec-4103-ad21-cd461ac2c477",track:{type:"6c488338-8eec-4103-ad21-cd461ac2c479"},time:["97aeb369-9aea-11d5-bd16-0090272ccb30"],vpn:["97aeb369-9aea-11d5-bd16-0090272ccb30"],comments:"Review preceding broad allow"},{uid:"lab-cp-30",type:"access-rule","rule-number":3,name:"Temporary-wide-access",enabled:true,source:["97aeb369-9aea-11d5-bd16-0090272ccb30"],destination:["97aeb369-9aea-11d5-bd16-0090272ccb30"],service:["97aeb369-9aea-11d5-bd16-0090272ccb30"],action:"6c488338-8eec-4103-ad21-cd461ac2c476",track:{type:"6c488338-8eec-4103-ad21-cd461ac2c479"},time:["97aeb369-9aea-11d5-bd16-0090272ccb30"],vpn:["97aeb369-9aea-11d5-bd16-0090272ccb30"]}]},null,2)
};

// Alternate native inputs use the same synthetic lab policies.
(function(){
  const core=window.FirewallReview,demos=window.FirewallReviewDemos;
  const fort=core.parse(demos.fortinet,'fortinet');
  const refs=(values,any)=>values.map(v=>({name:v===core.ANY?any:v}));
  demos.fortinetJSON=JSON.stringify({responses:[
    {http_method:'GET',status:'success',http_status:200,path:'firewall',name:'address',vdom:'root',results:[{name:'Lab-Servers',subnet:'10.30.0.0 255.255.255.0'}]},
    {http_method:'GET',status:'success',http_status:200,path:'firewall',name:'policy',vdom:'root',limit_reached:false,results:fort.rules.map(r=>({policyid:Number(r.id),name:r.name,srcintf:refs(r.from,'any'),dstintf:refs(r.to,'any'),srcaddr:refs(r.src,'all'),dstaddr:refs(r.dst,'all'),service:refs(r.service,'ALL'),action:r.action,status:r.enabled?'enable':'disable',schedule:r.schedule,comments:r.comment,...(r.logging!=='unknown'?{logtraffic:r.logging==='on'?'all':'disable'}:{}),...(r.protection!=='unknown'?{'utm-status':r.protection==='on'?'enable':'disable'}:{})}))}
  ]},null,2);
  const member=value=>({member:Array.isArray(value)?value:[value]});
  const base={'from':member('guest'),to:member('servers'),source:member('any'),destination:member('Lab-Servers'),application:member('any'),service:member('any'),'source-user':member('any'),'log-start':'no','log-end':'no'};
  const entries=[
    {...base,'@name':'Guest-to-Servers','@uuid':'lab-pa-10',action:'allow'},
    {...base,'@name':'Deny-Guest-SSH','@uuid':'lab-pa-20',application:member('ssh'),service:member('application-default'),action:'deny','log-end':'yes',description:'Review preceding broad allow'},
    {...base,'@name':'Temporary-wide-access','@uuid':'lab-pa-30',from:member('any'),to:member('any'),destination:member('any'),action:'allow','log-end':'yes','profile-setting':{group:member('Lab-Security-Profiles')}}
  ];
  demos.paloaltoJSON=JSON.stringify({config:{devices:{entry:[{'@name':'localhost.localdomain',vsys:{entry:[{'@name':'vsys1',rulebase:{security:{rules:{entry:entries}}}}]}}]}}},null,2);
  const lines=[],quote=v=>JSON.stringify(v);
  for(const r of entries){const prefix='set vsys vsys1 rulebase security rules '+quote(r['@name'])+' ';
    for(const [k,v] of Object.entries(r))if(!k.startsWith('@')){
      if(v?.member)lines.push(prefix+k+' [ '+v.member.map(quote).join(' ')+' ]');
      else if(k==='profile-setting')lines.push(prefix+'profile-setting group [ '+v.group.member.map(quote).join(' ')+' ]');
      else lines.push(prefix+k+' '+quote(v));
    }
  }demos.paloaltoCLI=lines.join('\n');
})();
