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
      {
        name: "Business Operations",
        summary: "Playbooks that preserve the financial hygiene, billing accuracy, procurement visibility, stakeholder updates, and executive dashboards.",
        summaryEs: "Playbooks que preservan la higiene financiera, la precisión de facturación, la visibilidad de compras, las actualizaciones a stakeholders y los tableros ejecutivos."
      },
      {
        name: "Contact Center (Beta)",
        summary: "Relationship-first omni-channel agents that combine sentiment cues with refreshed knowledge bases for rapid resolution.",
        summaryEs: "Agentes omnicanal centrados en la relación que combinan señales de sentimiento con bases de conocimiento actualizadas para una resolución rápida."
      },
      {
        name: "IT Support (Beta)",
        summary: "Incident-ready pods with documented triage, integrated telemetry, and continuity alignment across help desk tiers I–II.",
        summaryEs: "Pods listos para incidentes con triaje documentado, telemetría integrada y alineación de continuidad en los niveles I–II de mesa de ayuda."
      },
      {
        name: "Professionals",
        summary: "Insight teams providing predictive analytics, feedback frameworks, and growth-focused engagement models.",
        summaryEs: "Equipos de insights que entregan analítica predictiva, marcos de retroalimentación y modelos de engagement orientados al crecimiento."
      }
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

  function getFocus(lang){
    return lang==='es'
      ? SERVICE_DIRECTORY.overview.focusEs || SERVICE_DIRECTORY.overview.focus
      : SERVICE_DIRECTORY.overview.focus;
  }
  function getPillars(lang){
    return (SERVICE_DIRECTORY.servicePillars||[]).map(p => {
      const summary = lang==='es' ? (p.summaryEs || p.summary) : p.summary;
      return `${p.name} — ${summary}`;
    });
  }
  function getSolutions(lang){
    return (SERVICE_DIRECTORY.solutions||[]).map(s => {
      const coverage = lang==='es' ? (s.coverageEs || s.coverage) : s.coverage;
      return `${s.name} — ${coverage}`;
    });
  }
  function getProofPoints(lang){
    return lang==='es'
      ? SERVICE_DIRECTORY.proofPointsEs || SERVICE_DIRECTORY.proofPoints
      : SERVICE_DIRECTORY.proofPoints;
  }
  function getContactPaths(lang){
    return lang==='es'
      ? SERVICE_DIRECTORY.contactPathwaysEs || SERVICE_DIRECTORY.contactPathways
      : SERVICE_DIRECTORY.contactPathways;
  }

  const KB = [
    {
      id:"overview.en", lang:"en",
      q: /(what\s+is|who\s+are|about|overview|summary|intro|explain)\b|^ops\b|^chattia\b/i,
      a: () => `${SERVICE_DIRECTORY.overview.name} — ${getFocus("en")}
Pillars:
• ${getPillars("en").join("\n• ")}
Proof points: ${getProofPoints("en").join("; ")}.`
    },
    {
      id:"overview.es", lang:"es",
      q: /(qué\s+es|quiénes\s+son|acerca|resumen|introducción|explica|explicación)\b|^ops\b|^chattia\b/i,
      a: () => `${SERVICE_DIRECTORY.overview.name} — ${getFocus("es")}
Pilares:
• ${getPillars("es").join("\n• ")}
Resultados: ${getProofPoints("es").join("; ")}.`
    },
    { id:"pillars.en", lang:"en", q:/\b(pillars?|areas|capabilities|services|what\s+do\s+you\s+offer)\b/i,
      a:()=> `Service Pillars
- ${getPillars("en").join("\n- ")}`
    },
    { id:"pillars.es", lang:"es", q:/\b(pilares?|áreas|capacidades|servicios|qué\s+ofrecen|ofrecen)\b/i,
      a:()=> `Pilares de Servicio
- ${getPillars("es").join("\n- ")}`
    },
    { id:"solutions.en", lang:"en", q:/\b(solutions?|catalog|packages|what\s+problems|use\s+cases|examples)\b/i,
      a:()=> `Solutions
• ${getSolutions("en").join("\n• ")}`
    },
    { id:"solutions.es", lang:"es", q:/\b(soluciones?|catálogo|paquetes|casos\s+de\s+uso|ejemplos)\b/i,
      a:()=> `Soluciones
• ${getSolutions("es").join("\n• ")}`
    },
    { id:"proof.en", lang:"en", q:/\b(results?|metrics|proof|sla|availability|uptime|speed|security|compliance|nist|cisa|pci|soc2|gdpr|ccpa)\b/i,
      a:()=> `Operational Proof Points
- ${getProofPoints("en").join("\n- ")}`
    },
    { id:"proof.es", lang:"es", q:/\b(resultados?|métricas|pruebas|sla|disponibilidad|seguridad|cumplimiento|nist|cisa|pci|soc2|gdpr|ccpa)\b/i,
      a:()=> `Pruebas Operativas
- ${getProofPoints("es").join("\n- ")}`
    },
    { id:"contact.en", lang:"en", q:/\b(contact|reach|call|book|consult|hire|talk|email|phone|discovery)\b/i,
      a:()=> `Contact & Hiring Paths
- ${getContactPaths("en").join("\n- ")}
Share your context and preferred times; we reply within one business day.` },
    { id:"contact.es", lang:"es", q:/\b(contacto|llamar|agendar|consulta|contratar|hablar|correo|teléfono|descubrimiento)\b/i,
      a:()=> `Rutas de Contacto y Contratación
- ${getContactPaths("es").join("\n- ")}
Cuéntanos tu contexto y horarios; respondemos dentro de un día hábil.` }
  ];

  function pick(a){return a[(Math.random()*a.length)|0];}
  function detectLang(s, hint){ if(hint) return hint.toLowerCase().startsWith('es')?'es':'en'; return /[áéíóúñü¿¡]/i.test(s)?'es':'en'; }
  function isGreeting(s){ return /\b(hi|hello|hey|howdy|yo|hiya|good\s*(morning|afternoon|evening)|hola|buenas|qué\s*tal)\b/i.test(s); }

  function reply(userText, langHint){
    const text = (userText||"").trim();
    const lang = detectLang(text, langHint);
    if (!text || isGreeting(text)) return pick(lang==='es'?GREET_ES:GREET_EN);
    const bank = KB.filter(k=>k.lang===lang);
    for (const item of bank){ if (item.q.test(text)) return item.a(); }
    return (lang==='es')
      ? `${SERVICE_DIRECTORY.overview.name} — ${getFocus('es')}`
      : `${SERVICE_DIRECTORY.overview.name} — ${getFocus('en')}`;
  }

  window.FallbackKB = { reply };
})();
