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

/** Diccionario español→inglés para los textos que emite el backend (resúmenes
 * de auditoría, detalles de checks, narrativa del agente, disputas, errores).
 * Se aplican en orden: frases largas primero para evitar traducciones a medias. */
const BACKEND_PHRASES: Array<[RegExp, string]> = [
  // Narrativa del agente (core/agent_loop.py)
  [/Encontró (\d+) vuelos en la web \(búsqueda real\)\./g, "Found $1 flights on the web (real search)."],
  [/Encontró (\d+) hoteles en la web \(búsqueda real\)\./g, "Found $1 hotels on the web (real search)."],
  [/Aplicó el límite price_below de ([\d.]+) USD y eligió (.+?) de (.+?) por ([\d.]+) USD\./g, "Applied the price_below limit of $1 USD and chose $2 from $3 for $4 USD."],
  [/No encontró un límite price_below utilizable y eligió (.+?) de (.+?) por ([\d.]+) USD\./g, "Did not find a usable price_below limit and chose $1 from $2 for $3 USD."],
  [/La compra fue completada tras recibir APPROVE\./g, "The purchase was completed after APPROVE."],
  [/La compra no procedió: verify devolvió (\w+)\./g, "The purchase did not proceed: verify returned $1."],
  // 4.2: escenarios de demostración, anti-replay, firma del agente y moneda.
  [/Escenario de demostración '([a-z_]+)': oferta sintética \(no salió de una búsqueda real\) de (.+?) por ([\d.]+) USD\./g, "Demo scenario '$1': a synthetic offer (not from a real search) from $2 for $3 USD."],
  [/Verify devolvió (\w+); en un escenario nunca se compra\./g, "Verify returned $1; a scenario never buys anything."],
  [/Escenario de demostración: el mandato lo aprobaría, pero no se realizó ninguna compra\./g, "Demo scenario: the mandate would approve it, but no purchase was made."],
  [/Firma del agente válida sobre este intento\./g, "Valid agent signature on this attempt."],
  [/La firma del agente no corresponde a este intento o a este agente\./g, "The agent signature doesn't match this attempt or this agent."],
  [/Intento nuevo \(nonce no visto\)\./g, "New attempt (nonce not seen before)."],
  // 6.3: el intento declara cuándo se creó; uno viejo o "del futuro" se rechaza.
  [/Intento reciente\./g, "Recent attempt."],
  [/El intento no trae una fecha válida o es demasiado viejo \(más de 10 minutos\) o del futuro\./g, "The attempt has no valid creation time, or it is too old (over 10 minutes) or in the future."],
  [/Compra rechazada: el intento no es reciente\./g, "Purchase rejected: the attempt is not recent."],
  [/Intento sin nonce válido, o ya presentado antes \(replay\)\./g, "Attempt without a valid nonce, or already presented (replay)."],
  [/Compra rechazada: la firma del agente no es válida\./g, "Purchase rejected: the agent signature is not valid."],
  [/Compra rechazada: el intento ya fue presentado o no trae un nonce válido\./g, "Purchase rejected: the attempt was already presented or has no valid nonce."],
  [/La compra es en (\S+); el mandato autoriza solo (\S+)\./g, "The purchase is in $1; the mandate only authorizes $2."],
  [/Compra completada por Saturday: (.+?) por ([\d.]+) USD\./g, "Purchase completed by Saturday: $1 for $2 USD."],
  [/La búsqueda web no devolvió (?:vuelos|ofertas); el agente no intentó ninguna compra\./g, "The web search returned no offers; the agent did not attempt any purchase."],
  [/Saturday no encontró (?:vuelos|ofertas) en este momento\. No se realizó ningún intento de compra; intenta de nuevo\./g, "Saturday couldn't find offers right now. No purchase attempt was made; try again."],
  [/Vuelo más barato dentro de price_below\./g, "Cheapest flight within price_below."],
  [/No hubo vuelo dentro de price_below; se intentó el más barato disponible\./g, "No flight was within price_below; the cheapest available was attempted."],
  // Veredictos del guardián (api/verify.py)
  [/Compra aprobada por el mandato\./g, "Purchase approved by the mandate."],
  [/La compra requiere aprobación humana\./g, "The purchase requires human approval."],
  [/Requiere aprobación humana: falló /g, "Requires human approval — failed check: "],
  [/Compra rechazada: el mandato no existe\./g, "Purchase rejected: the mandate does not exist."],
  [/Compra rechazada: el mandato está revocado\./g, "Purchase rejected: the mandate is revoked."],
  [/Compra rechazada: el mandato está expirado\./g, "Purchase rejected: the mandate is expired."],
  [/Compra rechazada: el mandato está pausado\./g, "Purchase rejected: the mandate is paused."],
  // 5.1-5.3: engine en centavos, presupuesto mensual, reserva atómica e identidad del comercio.
  [/El mandato no define un límite de monto válido: no autoriza ninguna compra\./g, "The mandate has no valid amount limit, so it authorizes no purchase."],
  [/Monto inválido \(([^)]*)\): debe ser un entero de centavos mayor que cero\./g, "Invalid amount ($1): it must be a whole number of cents above zero."],
  [/El mandato no define (allowed_categories|allowed_merchants): no autoriza ninguna compra\./g, "The mandate doesn't define $1, so it authorizes no purchase."],
  [/Condición desconocida o mal formada: no se puede evaluar\./g, "Unknown or malformed condition: it can't be evaluated."],
  [/Las condiciones del mandato no son una lista\./g, "The mandate's conditions are not a list."],
  [/([\d.]+) <= ([\d.]+) este mes/g, "$1 <= $2 this month"],
  [/([\d.]+) gastado \+ ([\d.]+) supera el presupuesto mensual de ([\d.]+)/g, "$1 spent + $2 exceeds the monthly budget of $3"],
  [/Presupuesto mensual agotado/g, "Monthly budget used up"],
  [/Otra compra simultánea consumió el límite \((\w+)\) antes que esta\./g, "A simultaneous purchase used up the limit ($1) first."],
  [/Compra rechazada: el mandato ya no admite esta compra\./g, "Purchase rejected: the mandate no longer allows this purchase."],
  [/(\S+) coincide con el dominio de la oferta\./g, "$1 matches the offer's domain."],
  [/El comercio presentado \((\S+)\) no es el del dominio de la oferta \((\S+)\)\./g, "The presented merchant ($1) is not the one at the offer's domain ($2)."],
  [/Compra rechazada: el comercio no coincide con la fuente de la oferta\./g, "Purchase rejected: the merchant doesn't match the offer's source."],
  [/mandato pausado/g, "mandate paused"],
  [/Compra rechazada: el agente no coincide con el mandato\./g, "Purchase rejected: the agent does not match the mandate."],
  [/Compra rechazada: firma criptográfica inválida\./g, "Purchase rejected: invalid cryptographic signature."],
  [/Compra rechazada: la firma del mandato no es válida\./g, "Purchase rejected: the mandate signature is not valid."],
  // Detalles de checks (engine/)
  [/([\d.]+) no es menor que ([\d.]+)/g, "$1 is not below $2"],
  [/([\d.]+) excede el máximo de ([\d.]+)/g, "$1 exceeds the maximum of $2"],
  [/usos agotados \((\d+)\/(\d+)\)/g, "uses exhausted ($1/$2)"],
  [/sin límite/g, "no limit"],
  [/tipo de condición desconocido: /g, "unknown condition type: "],
  [/no está en \[/g, "is not in ["],
  [/permitida\b/g, "allowed"],
  [/permitido\b/g, "allowed"],
  [/Monto excede el máximo/g, "Amount exceeds the maximum"],
  [/Categoría no permitida/g, "Category not allowed"],
  [/Comercio no permitido/g, "Merchant not allowed"],
  [/Usos agotados/g, "Uses exhausted"],
  [/Entrada inválida/g, "Invalid input"],
  [/Error interno del motor de restricciones — rechazado por seguridad/g, "Internal constraint-engine error — rejected for safety"],
  // Firma / agente / estado (api/verify.py)
  [/Firma presente y estructurada\./g, "Signature present and well-formed."],
  [/Firma presente y verificada\./g, "Signature present and verified."],
  [/Firma digital Ed25519 válida\./g, "Valid Ed25519 digital signature."],
  // Paso 3.3: qué se verificó (firma del titular, sello del servidor o firma legada).
  [/Firma humana Ed25519 válida \(llave registrada del titular\)\./g, "Valid Ed25519 cardholder signature (registered key)."],
  [/El mandato no tiene una firma registrada\./g, "The mandate has no registered signature."],
  [/La llave que firmó este mandato fue revocada: el titular debe firmarlo de nuevo\./g, "The key that signed this mandate was revoked: the cardholder must sign it again."],
  [/La llave que firmó el mandato sigue activa\./g, "The key that signed the mandate is still active."],
  [/Compra rechazada: la llave que firmó el mandato fue revocada\./g, "Purchase rejected: the key that signed the mandate was revoked."],
  [/Firma humana inválida: falta el dueño o el registro del firmante\./g, "Invalid cardholder signature: the owner or signer record is missing."],
  [/Firma humana inválida: la llave del mandato no es la registrada al firmar\./g, "Invalid cardholder signature: the mandate's key is not the one registered at signing."],
  [/Firma humana inválida: la llave ya no pertenece al titular\./g, "Invalid cardholder signature: the key no longer belongs to the cardholder."],
  [/Firma humana inválida: el mandato guardado no cumple la especificación firmada\./g, "Invalid cardholder signature: the stored mandate doesn't match the signed specification."],
  [/Firma humana inválida: el mandato cambió después de firmarse\./g, "Invalid cardholder signature: the mandate changed after it was signed."],
  [/Firma humana inválida: la firma no verifica con la llave registrada\./g, "Invalid cardholder signature: it doesn't verify with the registered key."],
  [/El mandato no tiene un token de pago emitido por el servidor\./g, "The mandate has no server-issued payment token."],
  [/El token de pago no está atado a este mandato firmado\./g, "The payment token is not bound to this signed mandate."],
  [/Token de pago atado al mandato firmado\./g, "Payment token bound to the signed mandate."],
  [/Compra rechazada: el token de pago no corresponde a este mandato\./g, "Purchase rejected: the payment token doesn't belong to this mandate."],
  [/Compra rechazada: la moneda no es la autorizada en el mandato\./g, "Purchase rejected: the currency is not the one authorized in the mandate."],
  [/El titular autorizó compras sin estar presente\./g, "The cardholder authorized purchases without being present."],
  [/El titular no autorizó compras sin estar presente: cada compra requiere su aprobación\./g, "The cardholder did not authorize purchases without being present: each purchase needs their approval."],
  [/Firma digital inválida\./g, "Invalid digital signature."],
  [/Firma ausente o vacía\./g, "Signature missing or empty."],
  [/Agente autorizado\./g, "Agent authorized."],
  [/El agente que presenta el intento no está autorizado\./g, "The agent presenting the attempt is not authorized."],
  [/Mandato activo al momento de la revisión\./g, "Mandate active at the time of review."],
  [/Mandato activo\./g, "Mandate active."],
  [/Mandato no encontrado\.?/g, "Mandate not found."],
  [/mandato revocado/g, "mandate revoked"],
  [/mandato expirado/g, "mandate expired"],
  // Revisión humana (api/escalations.py)
  [/Aprobada por una persona\./g, "Approved by a person."],
  [/Rechazada por una persona\./g, "Declined by a person."],
  [/Compra aprobada por revisión humana tras la escalación\./g, "Purchase approved by human review after escalation."],
  [/Compra rechazada por revisión humana tras la escalación\./g, "Purchase declined by human review after escalation."],
  [/Escalada por (.+?) — revisada y APROBADA por una persona\./g, "Escalated for $1 — reviewed and APPROVED by a person."],
  [/Escalada por (.+?) — revisada y RECHAZADA por una persona\./g, "Escalated for $1 — reviewed and DECLINED by a person."],
  [/Este intento ya fue revisado por una persona\./g, "This attempt was already reviewed by a person."],
  [/El mandato está (mandate revoked|mandate expired|\w+): una revisión humana no puede aprobar compras sobre un mandato que ya no es válido\./g, "The mandate is $1: a human review cannot approve purchases on a mandate that is no longer valid."],
  [/Solo los intentos escalados admiten revisión humana; este quedó (\w+)\./g, "Only escalated attempts allow human review; this one was $1."],
  [/No existe una verificación registrada para ese intento en este mandato\./g, "There is no recorded verification for that attempt on this mandate."],
  [/La escalación no registró un monto verificable; no se puede aprobar\./g, "The escalation did not record a verifiable amount; it cannot be approved."],
  // Mandato / auditoría (api/main.py, core/mandate_store.py)
  [/Mandato creado para (.+?)\./g, "Mandate created for $1."],
  [/Mandato revocado por la persona autorizante\./g, "Mandate revoked by the authorizing person."],
  [/la persona autorizante/g, "the authorizing person"],
  // Disputas (api/disputes.py)
  [/Disputa (\S+) abierta por el titular: /g, "Dispute $1 filed by the cardholder: "],
  [/Disputa (\S+) resuelta: (\w+) responsable/g, "Dispute $1 resolved: $2 liable"],
  [/ — cargo válido, sin reembolso/g, " — valid charge, no refund"],
  [/ — reembolso emitido al titular\./g, " — refund issued to the cardholder."],
  [/El titular niega haber autorizado este cargo\./g, "The cardholder denies authorizing this charge."],
  [/No reconozco este cargo — el titular niega haberlo autorizado\./g, "I don't recognize this charge — the cardholder denies authorizing it."],
  [/La evidencia criptográfica del registro confirma que la compra fue verificada y aprobada dentro de un mandato activo y firmado por el titular\. La disputa se desestima\./g, "The ledger's cryptographic evidence confirms the purchase was verified and approved under an active mandate signed by the cardholder. The dispute is dismissed."],
  [/El comercio aceptó la compra \((.+?)\) DESPUÉS de que el mandato fue revocado \((.+?)\)\. El titular queda protegido\./g, "The merchant accepted the purchase ($1) AFTER the mandate was revoked ($2). The cardholder is protected."],
  [/El comercio procesó un pago contra un mandato que no existe en el registro\. El titular queda protegido\./g, "The merchant processed a payment against a mandate that does not exist in the registry. The cardholder is protected."],
  [/No existe una aprobación registrada para esta compra en el trail auditable \(no se verificó, o se rechazó, o quedó escalada sin aprobar\)\. El titular queda protegido\./g, "There is no approval for this purchase in the auditable trail (it was never verified, was rejected, or was escalated and never approved). The cardholder is protected."],
  [/El titular queda protegido\./g, "The cardholder is protected."],
  // OTP / errores HTTP frecuentes
  [/Código email OTP incorrecto o expirado\./g, "Incorrect or expired email OTP code."],
  [/Código OTP enviado a /g, "OTP code sent to "],
  [/Email verificado correctamente\./g, "Email verified successfully."],
];

/** Traduce el texto del backend a inglés (capa de presentación; el backend no cambia). */
export function translateBackendText(value: string): string {
  let text = value;
  for (const [pattern, replacement] of BACKEND_PHRASES) {
    text = text.replace(pattern, replacement);
  }
  return text;
}

export function localizedText(value: string): string {
  return displayName(translateBackendText(value))
    .replace(/\bAPPROVE\b/g, verdictLabel("APPROVE"))
    .replace(/\bESCALATE\b/g, verdictLabel("ESCALATE"))
    .replace(/\bREJECT\b/g, verdictLabel("REJECT"));
}

/** Ajusta la redacción de los checks sin alterar el valor técnico que entregó el motor. */
export function checkDetailLabel(rule: string, detail: string): string {
  if (rule === "category") {
    const technicalCategory = detail.split(" ")[0];
    const category = displayName(technicalCategory);
    if (detail.includes("permitida")) return `${category} allowed`;
    if (detail.includes("no está")) return `${category} is not an allowed category`;
  }
  if (rule === "merchant") {
    const technicalMerchant = detail.split(" ")[0];
    const merchant = displayName(technicalMerchant);
    if (detail.includes("permitido")) return `${merchant} authorized`;
    if (detail.includes("no está")) return `${merchant} is not an authorized merchant`;
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
