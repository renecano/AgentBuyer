/** Etiquetas humanas EN INGLÉS: el contrato interno con el backend no cambia
 * (el backend sigue emitiendo sus textos en español); esta capa de
 * presentación traduce todo lo visible para el usuario. */
export function verdictLabel(verdict?: string): string {
  switch (verdict) {
    case "APPROVE":
      return "APPROVED";
    case "ESCALATE":
      return "NEEDS APPROVAL";
    case "REJECT":
      return "REJECTED";
    default:
      return "NO VERDICT";
  }
}

export function auditTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    mandate_created: "mandate created",
    verification: "verification",
    scenario_verification: "demo scenario",
    revocation: "revocation",
    purchase_completed: "purchase completed",
    agent_run: "agent run",
    human_override_approved: "human approval",
    human_override_declined: "human decline",
    DISPUTE_FILED: "dispute filed",
    DISPUTE_RESOLVED: "dispute resolved",
  };
  return labels[type] ?? type.replace(/_/g, " ");
}

export function saturdayStateLabel(state: string): string {
  const labels: Record<string, string> = {
    idle: "STANDING BY",
    thinking: "ANALYZING",
    approve: "APPROVED",
    escalate: "NEEDS APPROVAL",
    reject: "REJECTED",
  };
  return labels[state] ?? state;
}

/** Estado vivo de un mandato tal como lo devuelve el backend (live_state.status). */
export type MandateStatus = "active" | "paused" | "revoked" | "expired";

/** 7.3: un mandato pausado o vencido se mostraba como "LOADING". */
export function mandateStatusLabel(status: MandateStatus | "loading"): string {
  return status === "loading" ? "LOADING" : status.toUpperCase();
}

/** Convierte identificadores de dominio en nombres legibles, incluso dentro de textos. */
export function displayName(value: string): string {
  const exactLabels: Record<string, string> = {
    "travel.flights": "Flights",
    "travel.hotels": "Hotels",
    "subscriptions": "Subscriptions",
    "digital.subscriptions": "Subscriptions",
    "mch_vuelaya": "VuelaYa",
  };
  if (exactLabels[value]) return exactLabels[value];
  if (/^fly_vy_\d+$/.test(value)) return `Flight ${Number(value.slice(-3))}`;
  if (value.startsWith("mch_")) return value.slice(4).replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  if (value.startsWith("travel.")) return value.slice(7).replace(/\b\w/g, (letter) => letter.toUpperCase());
  if (value.startsWith("mnd_")) return `Mandate ${value.slice(4).replace(/_/g, " ")}`;

  let readable = value;
  for (const [technical, label] of Object.entries(exactLabels)) {
    readable = readable.replace(new RegExp(technical.replace(".", "\\."), "g"), label);
  }
  return readable
    .replace(/fly_vy_(\d+)/g, (_, number: string) => `Flight ${Number(number)}`)
    .replace(/travel\.([a-z_]+)/g, (_, category: string) => category.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()))
    .replace(/mch_([a-z_]+)/g, (_, merchant: string) => merchant.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()));
}

// 7.3 (P-12): el backend responde en inglés. Antes este archivo traducía con ~120
// expresiones regulares del español del backend al inglés de la UI (cada texto nuevo
// del backend que no estaba en la lista llegaba en español). Ya no hace falta.

/** Textos del backend para la UI: nombres legibles para los identificadores y la
 * etiqueta de cada veredicto. El texto ya llega en inglés. */
export function localizedText(value: string): string {
  return displayName(value)
    .replace(/\bAPPROVE\b/g, verdictLabel("APPROVE"))
    .replace(/\bESCALATE\b/g, verdictLabel("ESCALATE"))
    .replace(/\bREJECT\b/g, verdictLabel("REJECT"));
}

/** Ajusta la redacción de los checks sin alterar el valor técnico que entregó el motor. */
export function checkDetailLabel(rule: string, detail: string): string {
  if (rule === "category") {
    const technicalCategory = detail.split(" ")[0];
    const category = displayName(technicalCategory);
    if (detail.endsWith(" allowed")) return `${category} allowed`;
    if (detail.includes(" is not in ")) return `${category} is not an allowed category`;
  }
  if (rule === "merchant") {
    const technicalMerchant = detail.split(" ")[0];
    const merchant = displayName(technicalMerchant);
    if (detail.endsWith(" allowed")) return `${merchant} authorized`;
    if (detail.includes(" is not in ")) return `${merchant} is not an authorized merchant`;
  }
  return localizedText(detail);
}

export function checkRuleLabel(rule: string): string {
  const labels: Record<string, string> = {
    mandate_exists: "Mandate exists",
    signature: "Signature",
    payment_token_binding: "Payment token",
    signing_key_active: "Signing key",
    nonce_fresh: "Not a replay",
    attempt_fresh: "Recent attempt",
    agent_signature: "Agent signature",
    semantic_firewall: "Semantic firewall",
    merchant_identity: "Merchant identity",
    monthly_budget: "Monthly budget",
    atomic_reservation: "Concurrent purchase",
    currency: "Currency",
    off_session_consent: "Buying without you",
    agent_identity: "Agent identity",
    status: "Mandate status",
    amount: "Amount",
    category: "Category",
    merchant: "Merchant",
    uses: "Uses remaining",
    "condition.price_below": "Price condition",
    "engine.internal_error": "Engine error",
  };
  return labels[rule] ?? displayName(rule);
}
