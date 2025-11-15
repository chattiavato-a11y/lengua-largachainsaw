export const SERVICE_DIRECTORY = Object.freeze({
  overview: {
    name: "OPS Remote Professional Network",
    focus:
      "Remote professionals delivering business operations, contact center, IT support, and specialists on demand."
  },
  servicePillars: [
    {
      name: "Business Operations",
      summary:
        "Playbooks that preserve financial hygiene, billing accuracy, procurement visibility, stakeholder updates, and executive dashboards."
    },
    {
      name: "Contact Center (Beta)",
      summary:
        "Relationship-first omni-channel agents that combine sentiment cues with refreshed knowledge bases for rapid resolution."
    },
    {
      name: "IT Support (Beta)",
      summary:
        "Incident-ready pods with documented triage, integrated telemetry, and continuity alignment across help desk tiers I–II."
    },
    {
      name: "Professionals",
      summary:
        "Insight teams providing predictive analytics, feedback frameworks, and growth-focused engagement models."
    }
  ],
  solutions: [
    {
      name: "Business Operations",
      coverage:
        "Billing, payables/receivables, vendor coordination, administrative support, marketing, and digital marketing assistance."
    },
    {
      name: "Contact Center (Beta)",
      coverage:
        "Multi-channel, relationship-driven CX with rapid-resolution support and loyalty-oriented engagement."
    },
    {
      name: "IT Support (Beta)",
      coverage:
        "End-to-end IT support with practical help desk coverage, ticketing, incident handling, and specialized support tracks."
    },
    {
      name: "Professionals On Demand",
      coverage:
        "Deployable assistants, specialists, and consultants for short-term sprints or long-term engagements."
    }
  ],
  proofPoints: [
    "24/7 follow-the-sun pods",
    "40% faster resolution",
    "99.95% availability",
    "12× security posture improvements (OPS CyberSec Core aligned)"
  ],
  talentNetwork: {
    applicationHighlights: [
      "Applicants showcase crafts, industries, skills, education, certifications, hobbies, continued education, achievements, and values.",
      "Guild interests: Business Operations, Contact Center, IT Support, Professionals, Analytics & Insights.",
      "Engagement models: full-time pods, part-time retainers, and project-based sprints."
    ],
    commitments: [
      "Inclusive, remote-first talent community",
      "Confidential intake with responses within one business day"
    ]
  },
  contactPathways: [
    "Discovery calls to map operational needs",
    "Direct OPS consultations for integrations and CX roadmaps",
    "Hire remote specialists across operations, CX, IT support, and on-demand talent"
  ],
  contentMetrics: {
    homepageCharacters: 3625,
    chatbotPanelCharacters: 138,
    talentApplicationCharacters: 1935,
    contactPageCharacters: 833
  }
});

function formatBulletedSection(title, lines) {
  return [`${title}:`, ...lines.map(line => `- ${line}`)].join("\n");
}

export const SERVICE_DIRECTORY_PROMPT = [
  "Use this OPS Remote Professional Network service directory as authoritative context for every response.",
  "Always ground answers in the catalog and explicitly connect recommendations to the appropriate pillar or solution when relevant.",
  "",
  `Overview: ${SERVICE_DIRECTORY.overview.name} — ${SERVICE_DIRECTORY.overview.focus}`,
  formatBulletedSection(
    "Service Pillars",
    SERVICE_DIRECTORY.servicePillars.map(pillar => `${pillar.name} – ${pillar.summary}`)
  ),
  formatBulletedSection(
    "Solutions",
    SERVICE_DIRECTORY.solutions.map(solution => `${solution.name} – ${solution.coverage}`)
  ),
  formatBulletedSection("Operational Proof Points", SERVICE_DIRECTORY.proofPoints),
  formatBulletedSection("Talent Network Highlights", SERVICE_DIRECTORY.talentNetwork.applicationHighlights),
  formatBulletedSection("Community Commitments", SERVICE_DIRECTORY.talentNetwork.commitments),
  formatBulletedSection("Contact & Hiring Pathways", SERVICE_DIRECTORY.contactPathways),
  "Content Metrics:",
  `- Homepage characters: ${SERVICE_DIRECTORY.contentMetrics.homepageCharacters}`,
  `- Chatbot panel characters: ${SERVICE_DIRECTORY.contentMetrics.chatbotPanelCharacters}`,
  `- Talent application characters: ${SERVICE_DIRECTORY.contentMetrics.talentApplicationCharacters}`,
  `- Contact page characters: ${SERVICE_DIRECTORY.contentMetrics.contactPageCharacters}`
].join("\n");
