(() => {
  const API_ENDPOINT = window.NETWORK_SECURITY_CHAT_ENDPOINT || "";
  const isLive = Boolean(API_ENDPOINT);

  const copy = {
    en:{
      open:'Open Network & Security Assistant', close:'Close chat', send:'Send message', input:'Your question',
      title:"Network & Security Assistant",
      status:isLive?"AI assistant":"",
      welcome:"Hi — ask me about network security assessments, incident response, firewall hardening, segmentation, troubleshooting, or automation.",
      placeholder:"Enter your question...",
      suggestions:["Firewall review","Incident response","Network assessment"],
      thinking:"Thinking…",
      error:"I couldn't reach the assistant right now. Please try again."
    },
    ro:{
      open:'Deschide asistentul de rețele și securitate', close:'Închide conversația', send:'Trimite mesajul', input:'Întrebarea ta',
      title:"Asistent Rețele & Securitate",
      status:isLive?"Asistent AI":"",
      welcome:"Salut — întreabă-mă despre evaluări de securitate, incident response, firewall hardening, segmentare, troubleshooting sau automatizare.",
      placeholder:"Scrie întrebarea...",
      suggestions:["Review firewall","Incident response","Evaluare rețea"],
      thinking:"Analizez…",
      error:"Nu pot contacta asistentul momentan. Încearcă din nou."
    },
    fr:{
      open:'Ouvrir l’assistant réseaux et sécurité', close:'Fermer la conversation', send:'Envoyer le message', input:'Votre question',
      title:"Assistant Réseaux & Sécurité",
      status:isLive?"Assistant IA":"",
      welcome:"Bonjour — posez une question sur les évaluations de sécurité réseau, la réponse aux incidents, le durcissement des firewalls, la segmentation, le dépannage ou l’automatisation.",
      placeholder:"Votre question...",
      suggestions:["Revue firewall","Réponse incident","Évaluation réseau"],
      thinking:"Analyse…",
      error:"Impossible de joindre l’assistant pour le moment. Réessayez."
    }
  };

  const demoAnswer = (q,lang) => {
    const s=q.toLowerCase();
    const answers={
      en:{
        firewall:"For a firewall review, start with management exposure, administrator access and MFA, policy hygiene, unused or overly broad rules, NAT, logging, firmware lifecycle, backups, and recovery readiness. Then prioritize findings by business impact and validate each remediation.",
        incident:"For incident response, begin by confirming scope, severity, ownership, evidence preservation, and decision authority. Contain only after you understand what evidence could be lost, then validate recovery and document lessons learned.",
        assessment:"A network security assessment should cover assets and exposed services, management planes, trust boundaries, privileged access, segmentation, logging, resilience, backups, and remediation priorities.",
        segment:"Start by mapping users, workloads, management systems, third parties, and critical services. Define trust boundaries, then review north-south and east-west paths and enforce least-privilege connectivity.",
        automat:"Use automation where work is repeatable and verifiable: configuration backup, pre/post checks, compliance validation, drift detection, reporting, and controlled changes.",
        troubleshoot:"Capture the last known-good state first. Then work from symptoms to evidence, form a hypothesis, test one variable at a time, and verify the outcome before closing the incident.",
        default:"This demo is currently limited to the site's core topics. Try asking about a firewall review, incident response, network security assessment, segmentation, troubleshooting, or automation."
      },
      ro:{
        firewall:"Pentru un review de firewall, începe cu expunerea managementului, accesul administratorilor și MFA, igiena politicilor, regulile neutilizate sau prea permisive, NAT, logging, lifecycle-ul firmware-ului, backup-urile și recovery readiness. Apoi prioritizează constatările după impact și validează remedierea.",
        incident:"Pentru incident response, confirmă mai întâi scopul, severitatea, ownership-ul, păstrarea dovezilor și autoritatea de decizie. Aplică containment după ce înțelegi ce dovezi pot fi pierdute, apoi validează recovery-ul și documentează lecțiile învățate.",
        assessment:"O evaluare de securitate a rețelei ar trebui să acopere activele și serviciile expuse, planele de management, trust boundaries, accesul privilegiat, segmentarea, logarea, reziliența, backup-urile și prioritățile de remediere.",
        segment:"Începe prin a mapa utilizatorii, workload-urile, sistemele de management, terții și serviciile critice. Definește trust boundaries, apoi verifică fluxurile north-south și east-west și aplică least privilege.",
        automat:"Folosește automatizarea acolo unde activitatea este repetabilă și verificabilă: backup de configurație, pre/post checks, compliance validation, drift detection, raportare și schimbări controlate.",
        troubleshoot:"Capturează mai întâi ultima stare cunoscută ca fiind bună. Apoi pornește de la simptome și dovezi, formulează o ipoteză, testează câte o variabilă și validează rezultatul înainte de închiderea incidentului.",
        default:"Acest demo este limitat momentan la ariile principale ale site-ului. Încearcă o întrebare despre firewall review, incident response, network security assessment, segmentare, troubleshooting sau automatizare."
      },
      fr:{
        firewall:"Pour une revue de firewall, commencez par l’exposition du plan de gestion, les accès administrateurs et le MFA, l’hygiène des politiques, les règles inutilisées ou trop larges, le NAT, la journalisation, le cycle de vie du firmware, les sauvegardes et la capacité de récupération. Priorisez ensuite les constats selon l’impact et validez chaque remédiation.",
        incident:"Pour la réponse aux incidents, confirmez d’abord le périmètre, la sévérité, les responsabilités, la préservation des preuves et l’autorité de décision. Contenez ensuite l’incident sans compromettre les preuves, puis validez la récupération et documentez les enseignements.",
        assessment:"Une évaluation de sécurité réseau doit couvrir les actifs et services exposés, les plans de gestion, les frontières de confiance, les accès privilégiés, la segmentation, la journalisation, la résilience, les sauvegardes et les priorités de remédiation.",
        segment:"Commencez par cartographier les utilisateurs, workloads, systèmes de gestion, tiers et services critiques. Définissez les frontières de confiance, puis examinez les flux nord-sud et est-ouest et appliquez le moindre privilège.",
        automat:"Automatisez les tâches répétables et vérifiables : sauvegarde de configuration, contrôles avant/après changement, validation de conformité, détection de dérive, reporting et changements contrôlés.",
        troubleshoot:"Capturez d’abord le dernier état connu comme fonctionnel. Passez ensuite des symptômes aux preuves, formulez une hypothèse, testez une variable à la fois et validez le résultat avant de clôturer l’incident.",
        default:"Cette démo est actuellement limitée aux principaux sujets du site. Essayez une question sur les firewalls, la réponse aux incidents, l’évaluation réseau, la segmentation, le dépannage ou l’automatisation."
      }
    };
    const a=answers[lang]||answers.en;
    if(/firewall|fortigate|palo alto|panorama/.test(s)) return a.firewall;
    if(/incident|ransom|breach|contain|response/.test(s)) return a.incident;
    if(/assess|audit|review|evalu|évalu/.test(s)) return a.assessment;
    if(/segment|vlan|vrf|zero trust|trust bound/.test(s)) return a.segment;
    if(/automat|ansible|compliance|drift|ci\/cd/.test(s)) return a.automat;
    if(/troubleshoot|diagnos|vpn|routing|sd-wan|outage/.test(s)) return a.troubleshoot;
    return a.default;
  };

  const launcher=document.createElement("button");
  launcher.className="va-chat-launcher";
  launcher.type="button";
  launcher.setAttribute("aria-label","Open Network & Security Assistant");
  launcher.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M4.75 5.75A2.75 2.75 0 0 1 7.5 3h9A2.75 2.75 0 0 1 19.25 5.75v7.5A2.75 2.75 0 0 1 16.5 16h-5.2l-4.42 3.68a.75.75 0 0 1-1.23-.58V16.9A2.75 2.75 0 0 1 4.75 14V5.75Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M8 8.5h8M8 11.75h5.25" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';

  const panel=document.createElement("section");
  panel.className="va-chat";
  panel.id="va-chat-panel";
  launcher.setAttribute("aria-controls",panel.id);
  launcher.setAttribute("aria-expanded","false");
  panel.setAttribute("aria-label","Network & Security Assistant");
  panel.innerHTML=`
    <div class="va-chat-head">
      <div class="va-chat-avatar" aria-hidden="true"><img src="assets/va-symbol.svg?v=2" alt=""></div>
      <div class="va-chat-title"><strong></strong><span></span></div>
      <button class="va-chat-close" type="button" aria-label="Close chat">×</button>
    </div>
    <div class="va-chat-messages" aria-live="polite"></div>
    <form class="va-chat-form">
      <textarea rows="1" maxlength="1200"></textarea>
      <button class="va-chat-send" type="submit" aria-label="Send message">↑</button>
    </form>`;

  document.body.append(launcher,panel);

  const messages=panel.querySelector(".va-chat-messages");
  const input=panel.querySelector("textarea");
  const send=panel.querySelector(".va-chat-send");
  const history=[];

  const lang=()=>["en","ro","fr"].includes(document.documentElement.lang)?document.documentElement.lang:"en";
  const add=(text,role,note)=>{
    const el=document.createElement("div");
    el.className=`va-msg ${role}`;
    el.textContent=text;
    el.lang=lang();
    messages.appendChild(el);
    if(note){
      const n=document.createElement("div");
      n.className="va-msg-note";n.textContent=note;messages.appendChild(n);
    }
    messages.scrollTop=messages.scrollHeight;
    return el;
  };
  let welcome;
  let suggestions;
  const refresh=()=>{
    const t=copy[lang()]||copy.en;
    panel.setAttribute("aria-label",t.title);
    launcher.setAttribute("aria-label",t.open);
    panel.querySelector(".va-chat-close").setAttribute("aria-label",t.close);
    send.setAttribute("aria-label",t.send);
    input.setAttribute("aria-label",t.input);
    panel.querySelector(".va-chat-title strong").textContent=t.title;
    panel.querySelector(".va-chat-title span").textContent=t.status;
    input.placeholder=t.placeholder;
    if(!welcome){
      welcome=add(t.welcome,"bot");
      suggestions=document.createElement("div");suggestions.className="va-chat-suggestions";
      t.suggestions.forEach((_,index)=>{
        const b=document.createElement("button");b.type="button";
        b.onclick=()=>{input.value=copy[lang()].suggestions[index];panel.querySelector("form").requestSubmit();};
        suggestions.appendChild(b);
      });
      messages.appendChild(suggestions);
    }
    welcome.textContent=t.welcome;welcome.lang=lang();
    [...suggestions.children].forEach((button,index)=>button.textContent=t.suggestions[index]);
  };
  const close=()=>{panel.classList.remove("is-open");launcher.setAttribute("aria-expanded","false");launcher.focus();};
  launcher.onclick=()=>{
    const open=panel.classList.toggle("is-open");
    launcher.setAttribute("aria-expanded",String(open));refresh();
    if(open) input.focus();
  };
  panel.querySelector(".va-chat-close").onclick=close;
  panel.addEventListener("keydown",event=>{if(event.key==="Escape"){event.preventDefault();close();}});
  document.addEventListener("site:languagechange",refresh);

  panel.querySelector("form").addEventListener("submit",async e=>{
    e.preventDefault();
    const q=input.value.trim();if(!q || send.disabled)return;
    input.value="";add(q,"user");send.disabled=true;
    const t=copy[lang()]||copy.en;
    const pending=add(t.thinking,"bot");
    try{
      let answer;
      if(isLive){
        const res=await fetch(API_ENDPOINT,{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({message:q,language:lang(),history:history.slice(-6)})
        });
        let data={};
        try{data=await res.json();}catch(_){}
        if(!res.ok)throw new Error(data.error||("HTTP "+res.status));
        answer=data.answer||data.response||t.error;
      }else{
        await new Promise(r=>setTimeout(r,300));
        answer=demoAnswer(q,lang());
      }
      pending.textContent=answer;
      history.push({role:"user",content:q},{role:"assistant",content:answer});
    }catch(error){
      const detail=error?.message&&error.message!=="Failed to fetch"?" "+error.message:"";
      pending.textContent=t.error+detail;
    }finally{
      send.disabled=false;messages.scrollTop=messages.scrollHeight;input.focus();
    }
  });

  input.addEventListener("keydown",e=>{
    if(e.key==="Enter"&&!e.shiftKey&&!e.isComposing){e.preventDefault();panel.querySelector("form").requestSubmit();}
  });

  refresh();
})();