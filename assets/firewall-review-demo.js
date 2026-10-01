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
