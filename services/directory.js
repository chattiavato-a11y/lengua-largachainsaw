export const SERVICE_DIRECTORY = Object.freeze({
  overview: {
    name: "OPS Remote Professional Network",
    focus:
      "Remote professionals delivering business operations, contact center, IT support, and specialists on demand.",
    focusEs:
      "Profesionales remotos que ofrecen operaciones de negocio, contact center, soporte de TI y especialistas bajo demanda."
  },
  servicePillars: [
    {
      name: "Business Operations",
      summary:
        "Playbooks that preserve financial hygiene, billing accuracy, procurement visibility, stakeholder updates, and executive dashboards.",
      summaryEs:
        "Playbooks que preservan la higiene financiera, la precisión de facturación, la visibilidad de compras, las actualizaciones a stakeholders y los tableros ejecutivos."
    },
    {
      name: "Contact Center (Beta)",
      summary:
        "Relationship-first omni-channel agents that combine sentiment cues with refreshed knowledge bases for rapid resolution.",
      summaryEs:
        "Agentes omnicanal centrados en la relación que combinan señales de sentimiento con bases de conocimiento actualizadas para una resolución rápida."
    },
    {
      name: "IT Support (Beta)",
      summary:
        "Incident-ready pods with documented triage, integrated telemetry, and continuity alignment across help desk tiers I–II.",
      summaryEs:
        "Pods listos para incidentes con triaje documentado, telemetría integrada y alineación de continuidad en los niveles I–II de mesa de ayuda."
    },
    {
      name: "Professionals",
      summary:
        "Insight teams providing predictive analytics, feedback frameworks, and growth-focused engagement models.",
      summaryEs:
        "Equipos de insights que entregan analítica predictiva, marcos de retroalimentación y modelos de engagement orientados al crecimiento."
    }
  ],
  solutions: [
    {
      name: "Business Operations",
      coverage:
        "Billing, payables/receivables, vendor coordination, administrative support, marketing, and digital marketing assistance.",
      coverageEs:
        "Facturación, cuentas por pagar/cobrar, coordinación con proveedores, soporte administrativo, marketing y acompañamiento en marketing digital."
    },
    {
      name: "Contact Center (Beta)",
      coverage:
        "Multi-channel, relationship-driven CX with rapid-resolution support and loyalty-oriented engagement.",
      coverageEs:
        "CX multicanal centrado en la relación con soporte de resolución rápida y engagement orientado a la lealtad."
    },
    {
      name: "IT Support (Beta)",
      coverage:
        "End-to-end IT support with practical help desk coverage, ticketing, incident handling, and specialized support tracks.",
      coverageEs:
        "Soporte TI de punta a punta con cobertura de mesa de ayuda, ticketing, manejo de incidentes y rutas de soporte especializado."
    },
    {
      name: "Professionals On Demand",
      coverage:
        "Deployable assistants, specialists, and consultants for short-term sprints or long-term engagements.",
      coverageEs:
        "Asistentes, especialistas y consultores desplegables para sprints cortos o compromisos de largo plazo."
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
  talentNetwork: {
    applicationHighlights: [
      "Applicants showcase crafts, industries, skills, education, certifications, hobbies, continued education, achievements, and values.",
      "Guild interests: Business Operations, Contact Center, IT Support, Professionals, Analytics & Insights.",
      "Engagement models: full-time pods, part-time retainers, and project-based sprints."
    ],
    applicationHighlightsEs: [
      "Las personas postulantes muestran oficios, industrias, habilidades, educación, certificaciones, hobbies, formación continua, logros y valores.",
      "Intereses de guild: Operaciones de Negocio, Contact Center, Soporte TI, Profesionales, Analytics & Insights.",
      "Modelos de engagement: pods de tiempo completo, retainers de medio tiempo y sprints por proyecto."
    ],
    commitments: [
      "Inclusive, remote-first talent community",
      "Confidential intake with responses within one business day"
    ],
    commitmentsEs: [
      "Comunidad de talento inclusiva y 100% remota",
      "Intake confidencial con respuesta en un día hábil"
    ]
  },
  contactPathways: [
    "Discovery calls to map operational needs",
    "Direct OPS consultations for integrations and CX roadmaps",
    "Hire remote specialists across operations, CX, IT support, and on-demand talent"
  ],
  contactPathwaysEs: [
    "Discovery calls para mapear necesidades operativas",
    "Consultorías directas con OPS para integraciones y roadmaps de CX",
    "Contrata especialistas remotos en operaciones, CX, soporte TI y talento on-demand"
  ],
  contentMetrics: {
    homepageCharacters: 3625,
    chatbotPanelCharacters: 138,
    talentApplicationCharacters: 1935,
    contactPageCharacters: 833
  }
});

export function formatBulletedSection(title, lines) {
  const items = (lines || []).filter(Boolean);
  if (!items.length) return "";
  return [`${title}:`, ...items.map((line) => `- ${line}`)].join("\n");
}

function buildServiceDirectoryPrompt(locale = "en") {
  const isEs = locale === "es";
  const t = (en, es) => (isEs ? es : en);

  const overview = SERVICE_DIRECTORY.overview || {};
  const overviewName = overview.name || "OPS Remote Professional Network";
  const focus = (isEs ? overview.focusEs || overview.focus : overview.focus) || "";

  const pillars = (SERVICE_DIRECTORY.servicePillars || []).map(
    (pillar) =>
      `${pillar.name} – ${
        isEs ? pillar.summaryEs || pillar.summary : pillar.summary
      }`
  );

  const solutions = (SERVICE_DIRECTORY.solutions || []).map(
    (solution) =>
      `${solution.name} – ${
        isEs ? solution.coverageEs || solution.coverage : solution.coverage
      }`
  );

  const proofPoints = isEs
    ? SERVICE_DIRECTORY.proofPointsEs || SERVICE_DIRECTORY.proofPoints
    : SERVICE_DIRECTORY.proofPoints;

  const talentHighlights = isEs
    ? SERVICE_DIRECTORY.talentNetwork.applicationHighlightsEs ||
      SERVICE_DIRECTORY.talentNetwork.applicationHighlights
    : SERVICE_DIRECTORY.talentNetwork.applicationHighlights;

  const commitments = isEs
    ? SERVICE_DIRECTORY.talentNetwork.commitmentsEs ||
      SERVICE_DIRECTORY.talentNetwork.commitments
    : SERVICE_DIRECTORY.talentNetwork.commitments;

  const contact = isEs
    ? SERVICE_DIRECTORY.contactPathwaysEs || SERVICE_DIRECTORY.contactPathways
    : SERVICE_DIRECTORY.contactPathways;

  const intro = [
    t(
      "Use this summary of the OPS Remote Professional Network when answering questions about OPS services and talent.",
      "Usa este resumen de OPS Remote Professional Network al responder preguntas sobre servicios y talento de OPS."
    ),
    t(
      "When it makes sense, connect your recommendations back to the pillars or solutions that best fit the situation.",
      "Cuando tenga sentido, vincula tus recomendaciones con los pilares o soluciones que mejor encajen con la situación."
    ),
    t(
      "Answer in the person’s preferred language (English or Spanish) and keep the OPS product names as they are.",
      "Responde en el idioma preferido de la persona (inglés o español) y mantén los nombres de productos OPS tal como están."
    )
  ];

  const bullets = [
    `${t("Overview", "Resumen")}: ${overviewName} — ${focus}`,
    formatBulletedSection(t("Service Pillars", "Pilares de Servicio"), pillars),
    formatBulletedSection(t("Solutions", "Soluciones"), solutions),
    formatBulletedSection(
      t("Operational Highlights", "Pruebas Operativas"),
      proofPoints
    ),
    formatBulletedSection(
      t("Talent Network Highlights", "Highlights de la Red de Talento"),
      talentHighlights
    ),
    formatBulletedSection(
      t("Community Commitments", "Compromisos con la Comunidad"),
      commitments
    ),
    formatBulletedSection(
      t("Contact & Hiring Pathways", "Rutas de Contacto y Contratación"),
      contact
    )
  ].filter(Boolean);

  const metrics = SERVICE_DIRECTORY.contentMetrics || {};
  const metricLines = [
    t("Content snapshot:", "Resumen de contenido:"),
    metrics.homepageCharacters
      ? `${t("- Homepage characters", "- Caracteres de la página de inicio")}: ${metrics.homepageCharacters}`
      : "",
    metrics.chatbotPanelCharacters
      ? `${t("- Chatbot panel characters", "- Caracteres del panel del chatbot")}: ${metrics.chatbotPanelCharacters}`
      : "",
    metrics.talentApplicationCharacters
      ? `${t(
          "- Talent application characters",
          "- Caracteres de la aplicación de talento"
        )}: ${metrics.talentApplicationCharacters}`
      : "",
    metrics.contactPageCharacters
      ? `${t(
          "- Contact page characters",
          "- Caracteres de la página de contacto"
        )}: ${metrics.contactPageCharacters}`
      : ""
  ].filter(Boolean);

  const sections = [
    ...intro,
    "",
    ...bullets,
    ...(metricLines.length ? ["", ...metricLines] : [])
  ].filter((line, idx, arr) => line !== "" || arr[idx - 1] !== "");

  return sections.join("\n");
}

export const SERVICE_DIRECTORY_PROMPTS = Object.freeze({
  en: buildServiceDirectoryPrompt("en"),
  es: buildServiceDirectoryPrompt("es")
});

export const SERVICE_DIRECTORY_PROMPT = SERVICE_DIRECTORY_PROMPTS.en;
