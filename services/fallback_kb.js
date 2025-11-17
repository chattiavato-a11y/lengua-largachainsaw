/* fallback_kb.js — client-side emergency fallback for Chattia (EN/ES)
   - Greets with many variants
   - Answers common questions from embedded OPS directory extracts
   - Exposes window.FallbackKB.reply(text, lang?)
*/
(function(){
  "use strict";

  const SERVICE_DIRECTORY = Object.freeze({
    overview: {
      name: "OPS Remote Professional Network",
      focus: "Remote professionals delivering business operations, contact center, IT support, and specialists on demand.",
      focusEs: "Profesionales remotos que ofrecen operaciones de negocio, contact center, soporte de TI y especialistas bajo demanda."
    },
    servicePillars: [
      { name: "Business Operations", summary: "Playbooks that preserve the financial hygiene, billing accuracy, procurement visibility, stakeholder updates, and executive dashboards." },
      { name: "Contact Center (Beta)", summary: "Relationship-first omni-channel agents that combine sentiment cues with refreshed knowledge bases for rapid resolution." },
      { name: "IT Support (Beta)", summary: "Incident-ready pods with documented triage, integrated telemetry, and continuity alignment across help desk tiers I–II." },
      { name: "Professionals", summary: "Insight teams providing predictive analytics, feedback frameworks, and growth-focused engagement models." }
    ],
    solutions: [
      {
        name: "Business Operations",
        coverage: "Billing, payables/receivables, vendor coordination, administrative support, marketing, and digital marketing assistance.",
        coverageEs: "Facturación, cuentas por pagar/cobrar, coordinación con proveedores, soporte administrativo, marketing y acompañamiento en marketing digital."
      },
      {
        name: "Contact Center (Beta)",
        coverage: "Multi-channel, relationship-driven CX with rapid-resolution support and loyalty-oriented engagement.",
        coverageEs: "CX multicanal centrado en la relación con soporte de resolución rápida y engagement orientado a la lealtad."
      },
      {
        name: "IT Support (Beta)",
        coverage: "End-to-end IT support with practical help desk coverage, ticketing, incident handling, and specialized support tracks.",
        coverageEs: "Soporte TI de punta a punta con cobertura de mesa de ayuda, ticketing, manejo de incidentes y rutas de soporte especializado."
      },
      {
        name: "Professionals On Demand",
        coverage: "Deployable assistants, specialists, and consultants for short-term sprints or long-term engagements.",
        coverageEs: "Asistentes, especialistas y consultores desplegables para sprints cortos o compromisos de largo plazo."
      }
    ],
    proofPoints: [
      "24/7 follow-the-sun pods",
      "40% faster resolution",
      "99.95% availability",
      "12× security posture improvements (OPS CyberSec Core aligned)"
    ],
    proofPointsEs: [
      "Pods 24/7 follow-the-sun",
      "Resolución 40% más rápida",
      "99.95% de disponibilidad",
      "Mejoras de 12× en la postura de seguridad (alineadas a OPS CyberSec Core)"
    ],
    contactPathways: [
      "Discovery calls to map operational needs",
      "Direct OPS consultations for integrations and CX roadmaps",
      "Hire remote specialists across operations, CX, IT support, and on-demand talent"
    ],
    contactPathwaysEs: [
      "Discovery calls para mapear necesidades operativas",
      "Consultorías directas con OPS para integraciones y roadmaps de CX",
      "Contrata especialistas remotos en operaciones, CX, soporte TI y talento on-demand"
    ]
  });

  const GREET_EN = [
    "Hi! I’m Chattia. How can I help today?",
    "Hello! I’m Chattia—ask me about services, pricing, or how to get started.",
    "Hey there! Need Business Ops, Contact Center, IT Support, or a specialist?",
    "Welcome! I can explain our pillars, solutions, or set up a discovery call.",
    "Good day! Tell me your goal and I’ll map options.",
    "Hi! Quick tour: Business Ops, Contact Center (beta), IT Support (beta), Professionals On-Demand.",
    "Hello! Ask me about availability, timelines, or security compliance.",
    "Hi! Want a concise overview or deep dive? I can do both."
  ];
  const GREET_ES = [
    "¡Hola! Soy Chattia. ¿En qué puedo ayudarte hoy?",
    "¡Bienvenido/a! Puedo explicarte servicios, precios o cómo empezar.",
    "¡Hey! ¿Necesitas Operaciones, Contact Center, Soporte IT o un especialista?",
    "¡Hola! Te guío por pilares, soluciones o agendamos una llamada.",
    "¡Buen día! Cuéntame tu objetivo y te propongo opciones.",
    "¡Hola! Tour rápido: Operaciones, Contact Center (beta), Soporte IT (beta), Profesionales On-Demand.",
    "¡Hola! Pregunta por disponibilidad, tiempos o cumplimiento de seguridad.",
    "¡Hola! ¿Prefieres un resumen o más detalle? Yo me adapto."
  ];

  const KB = [
    {
      id:"overview.en", lang:"en",
      q: /(what\s+is|who\s+are|about|overview|summary|intro|explain)\b|^ops\b|^chattia\b/i,
      a: () => `${SERVICE_DIRECTORY.overview.name} — ${SERVICE_DIRECTORY.overview.focus}
Pillars:
• ${getPillars("en").join("\n• ")}
Proof points: ${getProofPoints("en").join("; ")}.`
    },
    {
      id:"overview.es", lang:"es",
      q: /(qué\s+es|quiénes\s+son|acerca|resumen|introducción|explica|explicación)\b|^ops\b|^chattia\b/i,
      a: () => `${SERVICE_DIRECTORY.overview.name} — ${SERVICE_DIRECTORY.overview.focus}
Pilares:
• ${SERVICE_DIRECTORY.servicePillars[0].name} — ${SERVICE_DIRECTORY.servicePillars[0].summary}
• ${SERVICE_DIRECTORY.servicePillars[1].name} — ${SERVICE_DIRECTORY.servicePillars[1].summary}
• ${SERVICE_DIRECTORY.servicePillars[2].name} — ${SERVICE_DIRECTORY.servicePillars[2].summary}
• ${SERVICE_DIRECTORY.servicePillars[3].name} — ${SERVICE_DIRECTORY.servicePillars[3].summary}
Resultados: ${SERVICE_DIRECTORY.proofPoints.join("; ")}.`
    },
    { id:"pillars.en", lang:"en", q:/\b(pillars?|areas|capabilities|services|what\s+do\s+you\s+offer)\b/i,
      a:()=> `Service Pillars
- ${SERVICE_DIRECTORY.servicePillars[0].name}: ${SERVICE_DIRECTORY.servicePillars[0].summary}
- ${SERVICE_DIRECTORY.servicePillars[1].name}: ${SERVICE_DIRECTORY.servicePillars[1].summary}
- ${SERVICE_DIRECTORY.servicePillars[2].name}: ${SERVICE_DIRECTORY.servicePillars[2].summary}
- ${SERVICE_DIRECTORY.servicePillars[3].name}: ${SERVICE_DIRECTORY.servicePillars[3].summary}`
    },
    { id:"pillars.es", lang:"es", q:/\b(pilares?|áreas|capacidades|servicios|qué\s+ofrecen|ofrecen)\b/i,
      a:()=> `Pilares de Servicio
- ${SERVICE_DIRECTORY.servicePillars[0].name}: ${SERVICE_DIRECTORY.servicePillars[0].summary}
- ${SERVICE_DIRECTORY.servicePillars[1].name}: ${SERVICE_DIRECTORY.servicePillars[1].summary}
- ${SERVICE_DIRECTORY.servicePillars[2].name}: ${SERVICE_DIRECTORY.servicePillars[2].summary}
- ${SERVICE_DIRECTORY.servicePillars[3].name}: ${SERVICE_DIRECTORY.servicePillars[3].summary}`
    },
    { id:"solutions.en", lang:"en", q:/\b(solutions?|catalog|packages|what\s+problems|use\s+cases|examples)\b/i,
      a:()=> `Solutions
• ${SERVICE_DIRECTORY.solutions[0].name} — ${SERVICE_DIRECTORY.solutions[0].coverage}
• ${SERVICE_DIRECTORY.solutions[1].name} — ${SERVICE_DIRECTORY.solutions[1].coverage}
• ${SERVICE_DIRECTORY.solutions[2].name} — ${SERVICE_DIRECTORY.solutions[2].coverage}
• ${SERVICE_DIRECTORY.solutions[3].name} — ${SERVICE_DIRECTORY.solutions[3].coverage}`
    },
    { id:"solutions.es", lang:"es", q:/\b(soluciones?|catálogo|paquetes|casos\s+de\s+uso|ejemplos)\b/i,
      a:()=> `Soluciones
• ${SERVICE_DIRECTORY.solutions[0].name} — ${SERVICE_DIRECTORY.solutions[0].coverage}
• ${SERVICE_DIRECTORY.solutions[1].name} — ${SERVICE_DIRECTORY.solutions[1].coverage}
• ${SERVICE_DIRECTORY.solutions[2].name} — ${SERVICE_DIRECTORY.solutions[2].coverage}
• ${SERVICE_DIRECTORY.solutions[3].name} — ${SERVICE_DIRECTORY.solutions[3].coverage}`
    },
    { id:"proof.en", lang:"en", q:/\b(results?|metrics|proof|sla|availability|uptime|speed|security|compliance|nist|cisa|pci|soc2|gdpr|ccpa)\b/i,
      a:()=> `Operational Proof Points
- ${SERVICE_DIRECTORY.proofPoints.join("\n- ")}`
    },
    { id:"proof.es", lang:"es", q:/\b(resultados?|métricas|pruebas|sla|disponibilidad|seguridad|cumplimiento|nist|cisa|pci|soc2|gdpr|ccpa)\b/i,
      a:()=> `Pruebas Operativas
- ${SERVICE_DIRECTORY.proofPoints.join("\n- ")}`
    },
    { id:"contact.en", lang:"en", q:/\b(contact|reach|call|book|consult|hire|talk|email|phone|discovery)\b/i,
      a:()=> `Contact & Hiring Paths
- ${SERVICE_DIRECTORY.contactPathways.join("\n- ")}
Share your context and preferred times; we reply within one business day.` },
    { id:"contact.es", lang:"es", q:/\b(contacto|llamar|agendar|consulta|contratar|hablar|correo|teléfono|descubrimiento)\b/i,
      a:()=> `Rutas de Contacto y Contratación
- ${SERVICE_DIRECTORY.contactPathways.join("\n- ")}
Cuéntanos tu contexto y horarios; respondemos dentro de un día hábil.` }
  ];

  function pick(a){return a[(Math.random()*a.length)|0];}
  function detectLang(s, hint){ if(hint) return hint.toLowerCase().startsWith('es')?'es':'en'; return /[áéíóúñü¿¡]/i.test(s)?'es':'en'; }
  function isGreeting(s){ return /\b(hi|hello|hey|howdy|yo|hiya|good\s*(morning|afternoon|evening)|hola|buenas|qué\s*tal)\b/i.test(s); }

  function toResponse(text, lang, matchId=null){
    const safeText = String(text || "").trim();
    return { text: safeText || "", lang, matchId };
  }

  function reply(userText, langHint){
    const text = (userText||"").trim();
    const lang = detectLang(text, langHint);
    if (!text || isGreeting(text)) return toResponse(pick(lang==='es'?GREET_ES:GREET_EN), lang, "greeting");
    const bank = KB.filter(k=>k.lang===lang);
    for (const item of bank){ if (item.q.test(text)) return toResponse(item.a(), lang, item.id); }
    return toResponse(
      lang==='es'
        ? `${SERVICE_DIRECTORY.overview.name} — ${getFocus('es')}`
        : `${SERVICE_DIRECTORY.overview.name} — ${getFocus('en')}`,
      lang,
      "fallback.overview"
    );
  }

  window.FallbackKB = { reply };
})();
