const ALLOWED_ORIGINS = new Set([
  "https://eolthecrow.github.io",
  "http://localhost:8000",
  "http://127.0.0.1:8000"
]);

const SYSTEM_PROMPT = `
You are the Network & Security Assistant for Vladimir Arjoca's Network & Security Advisory website.

Scope:
- Cybersecurity incident response
- Network security assessments
- Firewall security and hardening
- Network architecture and segmentation
- Troubleshooting and incident diagnostics
- Network automation and compliance

Methodology:
1. Assess: understand architecture, exposure, controls, dependencies and evidence.
2. Prioritize: translate findings into risks, priorities, owners and practical remediation.
3. Improve: implement, validate, document and make the improvement repeatable.

Guidance:
- Be concise, technical, practical and vendor-neutral by default.
- You may discuss Fortinet, Palo Alto Networks, Cisco and Ansible when relevant.
- Do not invent client engagements, certifications, project results or personal claims.
- Do not claim that the site or its resources are fully compliant with a framework unless the user provides evidence.
- For destructive, risky or production-changing actions, recommend validation, backups and change control.
- If a question is unrelated to network/security engineering, politely keep the answer within the website's scope.
`;

function cors(origin){
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods":"POST,OPTIONS",
    "Access-Control-Allow-Headers":"Content-Type",
    "Vary":"Origin"
  };
}

export default {
  async fetch(request, env) {
    const origin=request.headers.get("Origin")||"";
    if(!ALLOWED_ORIGINS.has(origin)) return new Response("Forbidden",{status:403});

    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors(origin)});
    if(request.method!=="POST") return new Response("Method not allowed",{status:405,headers:cors(origin)});

    try{
      const body=await request.json();
      const message=String(body.message||"").trim();
      const language=["en","ro","fr"].includes(body.language)?body.language:"en";
      if(!message || message.length>1200){
        return Response.json({error:"Invalid message"},{status:400,headers:cors(origin)});
      }

      const prior=Array.isArray(body.history)?body.history.slice(-6):[];
      const messages=[
        {role:"system",content:SYSTEM_PROMPT+"\nReply in "+({en:"English",ro:"Romanian",fr:"French"}[language])+"."},
        ...prior
          .filter(x=>x && ["user","assistant"].includes(x.role) && typeof x.content==="string")
          .map(x=>({role:x.role,content:x.content.slice(0,1800)})),
        {role:"user",content:message}
      ];

      const result=await env.AI.run("@cf/google/gemma-4-26b-a4b-it",{
        messages,
        max_tokens:550,
        temperature:0.25,
        chat_template_kwargs:{enable_thinking:false}
      });

      const answer=result?.response || result?.result?.response || String(result?.response||"");
      return Response.json({answer},{headers:{...cors(origin),"Cache-Control":"no-store"}});
    }catch(error){
      return Response.json({error:"Assistant unavailable"},{status:500,headers:cors(origin)});
    }
  }
};