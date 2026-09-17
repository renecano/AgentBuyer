import { FormEvent, useMemo, useState, useEffect, useRef } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Saturday, { type SaturdayExpression } from "./Saturday";
import { ApiError, request } from "../lib/api";
import { LoginRateLimitedError, type AccessToken, type EmailLoginStart } from "../lib/authApi";
import { useAuth } from "../lib/AuthProvider";

type MandateCreatorProps = {
  onCreated: (mandateId: string) => void;
  /** Continúa el relato automático en Mission Control después de emitir el mandato. */
  onDemoCreated?: (mandateId: string) => void;
};

type VerificationStatus = "pending" | "processing" | "complete";

function verificationStatus(complete: boolean, processing: boolean): VerificationStatus {
  return complete ? "complete" : processing ? "processing" : "pending";
}

const verificationStatusLabel: Record<VerificationStatus, string> = {
  pending: "PENDING",
  processing: "IN PROGRESS",
  complete: "COMPLETED",
};

const categories = [
  { value: "travel.flights", label: "Flights" },
  { value: "travel.hotels", label: "Hotels" },
];

const merchants = [
  { value: "mch_vuelaya", label: "VuelaYa" },
  { value: "mch_despegar", label: "Despegar" },
  { value: "mch_kayak", label: "Kayak" },
  { value: "mch_expedia", label: "Expedia" },
];

// Suma noches a una fecha YYYY-MM-DD (check-out del hotel).
function addDays(value: string, days: number) {
  const date = dateFromKey(value);
  date.setDate(date.getDate() + days);
  return dateKey(date);
}

function endOfMonth() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);
}

// Fecha cercana (~2 semanas) para que la búsqueda web real devuelva resultados
// de forma confiable — las fechas muy lejanas suelen no tener tarifas publicadas.
function nearTermDate() {
  const d = new Date();
  d.setDate(d.getDate() + 14);
  return d.toISOString().slice(0, 10);
}

function safeId(value: string, prefix: string) {
  const readable = value.trim().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "") || "persona";
  return `${prefix}_${readable}_${Date.now().toString(36)}`;
}

function dateKey(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function dateFromKey(value: string) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(year, month - 1, day);
}

function readableDate(value: string) {
  return new Intl.DateTimeFormat("en-US", { day: "numeric", month: "short", year: "numeric" })
    .format(dateFromKey(value))
    .replace(".", "");
}

type CalendarDatePickerProps = {
  value: string;
  onChange: (value: string) => void;
  ariaLabel?: string;
};

function CalendarDatePicker({ value, onChange, ariaLabel = "Pick a date" }: CalendarDatePickerProps) {
  const today = useMemo(() => {
    const current = new Date();
    current.setHours(0, 0, 0, 0);
    return current;
  }, []);
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    function closeOnOutsideClick(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) setIsOpen(false);
    }
    document.addEventListener("mousedown", closeOnOutsideClick);
    return () => document.removeEventListener("mousedown", closeOnOutsideClick);
  }, [isOpen]);
  const [visibleMonth, setVisibleMonth] = useState(() => {
    const selected = value ? dateFromKey(value) : today;
    return new Date(selected.getFullYear(), selected.getMonth(), 1);
  });
  const monthStart = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth(), 1);
  const gridStart = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth(), 1 - monthStart.getDay());
  const days = Array.from({ length: 42 }, (_, index) => {
    const day = new Date(gridStart);
    day.setDate(gridStart.getDate() + index);
    return day;
  });
  const monthLabel = new Intl.DateTimeFormat("en-US", { month: "long", year: "numeric" }).format(visibleMonth);
  const earliestMonth = new Date(today.getFullYear(), today.getMonth(), 1);

  function togglePicker() {
    if (!isOpen) {
      const selected = value ? dateFromKey(value) : today;
      setVisibleMonth(new Date(selected.getFullYear(), selected.getMonth(), 1));
    }
    setIsOpen((open) => !open);
  }

  return (
    <div className="date-picker" ref={containerRef}>
      <button className={`date-picker-trigger ${value ? "has-value" : ""}`} type="button" onClick={togglePicker} aria-haspopup="dialog" aria-expanded={isOpen}>
        <span>{value ? readableDate(value) : "Pick a date"}</span><b aria-hidden="true">⌄</b>
      </button>
      {isOpen && <div className="calendar-popover" role="dialog" aria-label={ariaLabel}>
        <div className="calendar-heading">
          <button type="button" onClick={() => setVisibleMonth(new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() - 1, 1))} disabled={visibleMonth <= earliestMonth} aria-label="Previous month">‹</button>
          <strong>{monthLabel}</strong>
          <button type="button" onClick={() => setVisibleMonth(new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() + 1, 1))} aria-label="Next month">›</button>
        </div>
        <div className="calendar-weekdays">{["S", "M", "T", "W", "T", "F", "S"].map((day, index) => <span key={`${day}-${index}`}>{day}</span>)}</div>
        <div className="calendar-days">
          {days.map((day) => {
            const key = dateKey(day);
            const isPast = day < today;
            const outsideMonth = day.getMonth() !== visibleMonth.getMonth();
            return <button className={`${outsideMonth ? "outside-month" : ""} ${key === value ? "is-selected" : ""}`} type="button" disabled={isPast} key={key} onClick={() => { onChange(key); setIsOpen(false); }}>{day.getDate()}</button>;
          })}
        </div>
      </div>}
    </div>
  );
}

type WizardStep = 1 | 2 | 3;
const WIZARD_STEPS = 3;

type WizardDemoStage = "idle" | "preparing" | "signin" | "awaiting_code" | "limits" | "authorizing" | "paused" | "error";

// Datos de la demo: neutros y claramente ficticios.
const DEMO_MARTA = {
  name: "Marta",
  document: "DEMO-ID-000000",
  phone: "+00 000 000 0000",
  email: "marta@example.com",
  amount: "150",
  uses: "3",
  price: "150",
  origin: "BUE",
  destination: "COR",
};

const WIZARD_DEMO_LABELS: Record<Exclude<WizardDemoStage, "idle" | "paused" | "error">, string> = {
  preparing: "Marta starts a new permission",
  signin: "Signing in with a one-time email code…",
  awaiting_code: "Enter the code sent to your email to continue the demo.",
  limits: "Setting verifiable limits…",
  authorizing: "Issuing the mandate…",
};

const EMAIL_PATTERN = /^\S+@\S+\.\S+$/;

class DemoCancelledError extends Error {}

function withTimeout<T>(promise: Promise<T>, milliseconds = 8000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => reject(new Error("The request took too long. You can continue manually.")), milliseconds);
    promise.then((value) => { window.clearTimeout(timer); resolve(value); }, (reason) => { window.clearTimeout(timer); reject(reason); });
  });
}

type Outcome<T> = { ok: true; value: T } | { ok: false; message: string };

export default function MandateCreator({ onCreated, onDemoCreated }: MandateCreatorProps) {
  const { session, isAuthenticated, sessionNotice, startEmailLogin, verifyEmailLogin, logout } = useAuth();

  // Límites prellenados con valores de demo (no son datos personales).
  const [humanName, setHumanName] = useState("Marta");
  const [maxAmount, setMaxAmount] = useState("150");
  const [category, setCategory] = useState("travel.flights");
  const [merchant, setMerchant] = useState("mch_vuelaya");
  const [maxUses, setMaxUses] = useState("3");
  const [priceBelow, setPriceBelow] = useState("150");
  const [validUntil, setValidUntil] = useState(endOfMonth());
  // Estos datos viajan con el permiso para que Saturday pueda buscar la ruta real.
  // Ruta por defecto BUE→COR con fecha cercana: combinación confirmada que
  // la búsqueda web real devuelve de forma confiable para la demo.
  const [flightOrigin, setFlightOrigin] = useState("BUE");
  const [flightDestination, setFlightDestination] = useState("COR");
  const [departureDate, setDepartureDate] = useState(nearTermDate());
  // Campos de hotel: dónde, check-in y cuántas noches (check-out se calcula).
  const [hotelDestination, setHotelDestination] = useState("Cordoba, Argentina");
  const [hotelCheckIn, setHotelCheckIn] = useState(nearTermDate());
  const [hotelNights, setHotelNights] = useState("3");
  const [currentStep, setCurrentStep] = useState<WizardStep>(1);

  // Datos de contacto: los escribe la persona (sin valores precargados).
  const [userIdDoc, setUserIdDoc] = useState("");
  const [userPhone, setUserPhone] = useState("");
  // El email es la identidad: se verifica con un código de un solo uso.
  const [userEmail, setUserEmail] = useState(session?.email ?? "");

  // Login por código (OTP) de email.
  const [codeSent, setCodeSent] = useState(false);
  const [emailHint, setEmailHint] = useState("");
  const [codeDemo, setCodeDemo] = useState<string | null>(null);
  const [loginCode, setLoginCode] = useState("");
  const [sendingCode, setSendingCode] = useState(false);
  const [verifyingCode, setVerifyingCode] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [cooldownUntil, setCooldownUntil] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const [sensitiveFieldFocused, setSensitiveFieldFocused] = useState(false);
  const [editingIdentity, setEditingIdentity] = useState(false);
  const [microExpression, setMicroExpression] = useState<SaturdayExpression | null>(null);
  const expressionTimer = useRef<number | null>(null);
  const demoPauseResolver = useRef<(() => void) | null>(null);
  const demoPauseTimer = useRef<number | null>(null);
  const demoLogin = useRef<{ resolve: (token: AccessToken) => void; reject: (reason: Error) => void } | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [wizardDemoStage, setWizardDemoStage] = useState<WizardDemoStage>("idle");
  const [showWizardDemoLabel, setShowWizardDemoLabel] = useState(false);

  const selectedCategory = categories.find((item) => item.value === category)?.label ?? category;
  const selectedMerchant = merchants.find((item) => item.value === merchant)?.label ?? merchant;
  // Un teléfono real: al menos 10 dígitos (ignorando espacios, guiones, etc.).
  const phoneDigits = userPhone.replace(/\D/g, "");
  const phoneComplete = phoneDigits.length >= 10;
  const identityComplete = Boolean(userIdDoc.trim() && phoneComplete);
  const identityCollapsed = identityComplete && !editingIdentity;
  const stepOneReady = identityComplete && isAuthenticated;
  const completedVerificationCount = Number(identityComplete) + Number(isAuthenticated);
  const identityStatus = verificationStatus(identityComplete, Boolean(userIdDoc.trim() || userPhone.trim()));
  const signInStatus = verificationStatus(isAuthenticated, codeSent || sendingCode || verifyingCode);
  const cooldownSeconds = cooldownUntil !== null ? Math.max(0, Math.ceil((cooldownUntil - now) / 1000)) : 0;
  const saturdayExpression: SaturdayExpression | undefined = sensitiveFieldFocused
    ? "covering"
    : microExpression ?? (stepOneReady ? "ready" : undefined);
  const summary = useMemo(
    () => `Saturday will be able to buy ${selectedCategory.toLowerCase()} at ${selectedMerchant}, up to $${maxAmount || "—"} per purchase, at most ${maxUses || "—"} times, only if the price drops below $${priceBelow || "—"}${validUntil ? `, valid until ${validUntil}.` : "."}${session ? ` Authorized by ${session.email}.` : ""}`,
    [maxAmount, maxUses, priceBelow, selectedCategory, selectedMerchant, validUntil, session],
  );

  // Si la sesión se cae (expiró o el backend devolvió 401), el wizard vuelve al
  // paso de login con el estado del código limpio: quedarse en "Confirmar" con
  // un botón que ya no puede autorizar sería exactamente la sorpresa a evitar.
  useEffect(() => {
    if (isAuthenticated || sessionNotice === null) return;
    setCurrentStep(1);
    setCodeSent(false);
    setCodeDemo(null);
    setLoginCode("");
    setLoginError(null);
  }, [isAuthenticated, sessionNotice]);

  // Cuenta regresiva del cooldown del 429 (Retry-After).
  useEffect(() => {
    if (cooldownUntil === null) return undefined;
    const interval = window.setInterval(() => {
      const current = Date.now();
      setNow(current);
      if (current >= cooldownUntil) setCooldownUntil(null);
    }, 1000);
    return () => window.clearInterval(interval);
  }, [cooldownUntil]);

  function showMicroExpression(expression: SaturdayExpression) {
    if (expressionTimer.current !== null) window.clearTimeout(expressionTimer.current);
    setMicroExpression(expression);
    expressionTimer.current = window.setTimeout(() => setMicroExpression(null), 850);
  }

  async function sendLoginCode(emailOverride?: string): Promise<Outcome<EmailLoginStart>> {
    const email = (emailOverride ?? userEmail).trim();
    if (!EMAIL_PATTERN.test(email)) {
      const message = "Enter a valid email (name@domain.com) to receive your sign-in code.";
      setLoginError(message);
      return { ok: false, message };
    }
    setSendingCode(true);
    setLoginError(null);
    try {
      const started = await startEmailLogin(email);
      setCodeSent(true);
      setEmailHint(started.emailHint);
      setCodeDemo(started.codeDemo);
      setLoginCode("");
      return { ok: true, value: started };
    } catch (caught) {
      let message = caught instanceof Error ? caught.message : "We couldn't send the sign-in code.";
      if (caught instanceof LoginRateLimitedError) {
        message = "Too many code requests for this email.";
        if (caught.retryAfterSeconds !== null) {
          setNow(Date.now());
          setCooldownUntil(Date.now() + caught.retryAfterSeconds * 1000);
        }
      }
      setLoginError(message);
      return { ok: false, message };
    } finally {
      setSendingCode(false);
    }
  }

  async function verifyLoginCode(emailOverride?: string, codeOverride?: string): Promise<Outcome<AccessToken>> {
    const email = (emailOverride ?? userEmail).trim();
    const code = (codeOverride ?? loginCode).trim();
    if (!/^\d{6}$/.test(code)) {
      const message = "The code must be exactly 6 digits.";
      setLoginError(message);
      return { ok: false, message };
    }
    setVerifyingCode(true);
    setLoginError(null);
    try {
      const token = await verifyEmailLogin(email, code);
      setUserEmail(token.email);
      setCodeSent(false);
      setCodeDemo(null);
      setLoginCode("");
      showMicroExpression("happy");
      demoLogin.current?.resolve(token);
      demoLogin.current = null;
      return { ok: true, value: token };
    } catch (caught) {
      let message = caught instanceof Error ? caught.message : "We couldn't verify the code.";
      if (caught instanceof ApiError && caught.status === 429) {
        // Se agotaron los intentos: el código quedó invalidado, hay que pedir otro.
        message = "Too many failed attempts. Request a new code.";
        setCodeSent(false);
        setCodeDemo(null);
      } else if (caught instanceof ApiError && caught.status === 401) {
        message = "Incorrect or expired code.";
      }
      setLoginError(message);
      return { ok: false, message };
    } finally {
      setVerifyingCode(false);
    }
  }

  function signOut() {
    logout();
    setCodeSent(false);
    setCodeDemo(null);
    setLoginCode("");
    setLoginError(null);
  }

  async function submitMandate(demo = false, verifiedEmail: string | null = isAuthenticated && session ? session.email : null): Promise<boolean> {
    setError(null);
    if (!verifiedEmail) {
      setError("Sign in with the code sent to your email before authorizing Saturday.");
      setCurrentStep(1);
      return false;
    }
    // La demo puede arrancar con el wizard vacío: el payload se construye con
    // los mismos valores que se muestran, sin depender de un re-render previo.
    const demoValues = demo ? {
      name: humanName || DEMO_MARTA.name,
      document: userIdDoc || DEMO_MARTA.document,
      phone: userPhone || DEMO_MARTA.phone,
      amount: maxAmount || DEMO_MARTA.amount,
      uses: maxUses || DEMO_MARTA.uses,
      price: priceBelow || DEMO_MARTA.price,
      origin: flightOrigin || DEMO_MARTA.origin,
      destination: flightDestination || DEMO_MARTA.destination,
      date: departureDate || nearTermDate(),
    } : { name: humanName, document: userIdDoc, phone: userPhone, amount: maxAmount, uses: maxUses, price: priceBelow, origin: flightOrigin, destination: flightDestination, date: departureDate };
    const amount = Number(demoValues.amount);
    const uses = Number(demoValues.uses);
    const price = Number(demoValues.price);
    // Si falta algo del paso de límites, regresamos ahí para que el error sea accionable.
    if (!demoValues.name.trim() || !Number.isFinite(amount) || amount <= 0 || !Number.isInteger(uses) || uses <= 0 || !Number.isFinite(price) || price <= 0) {
      setError("Fill in your name and the limits with valid numbers greater than zero.");
      setCurrentStep(2);
      return false;
    }

    if (category === "travel.flights" && (!demoValues.origin.trim() || !demoValues.destination.trim() || !demoValues.date)) {
      setError("Fill in origin, destination, and departure date to search for flights.");
      setCurrentStep(2);
      return false;
    }
    const nights = Number(hotelNights);
    if (category === "travel.hotels" && (!hotelDestination.trim() || !hotelCheckIn || !Number.isInteger(nights) || nights <= 0)) {
      setError("Fill in the destination, check-in date, and a valid number of nights to search for hotels.");
      setCurrentStep(2);
      return false;
    }
    if (!category || !merchant) {
      setError("Choose a category and a merchant for the permission.");
      setCurrentStep(2);
      return false;
    }

    const mandateId = safeId(demoValues.name, "mnd");
    // Sin firma, token de pago ni "autenticación" declarados por el cliente: el
    // servidor genera el payment_token y firma el mandato con Ed25519.
    const payload = {
      mandate_id: mandateId,
      human: {
        id: safeId(demoValues.name, "hum"),
        display_name: demoValues.name.trim(),
        id_document: demoValues.document,
        phone: demoValues.phone,
        // Email verificado por OTP: destino del recibo de compra (core/notifications).
        email: verifiedEmail,
      },
      agent: { id: "agt_saturday", display_name: "Saturday" },
      ...(category === "travel.flights" ? {
        search_fields: {
          origin: demoValues.origin.trim(),
          destination: demoValues.destination.trim(),
          departure_date: demoValues.date,
        },
      } : category === "travel.hotels" ? {
        search_fields: {
          destination: hotelDestination.trim(),
          check_in: hotelCheckIn,
          check_out: addDays(hotelCheckIn, nights),
          nights,
        },
      } : {}),
      constraints: {
        max_amount_per_purchase: amount,
        currency: "USD",
        allowed_categories: [category],
        // Solo el comercio que la persona eligió: si la mejor oferta real viene
        // de otro sitio, el mandato NO se cumple al 100% y el guardián escala
        // a la persona (human-in-the-loop) en vez de comprar en silencio.
        allowed_merchants: [merchant],
        max_uses: uses,
        conditions: [{ type: "price_below", value: price }],
        off_session_consent: true,
      },
      ...(validUntil ? { valid_until: validUntil } : {}),
    };

    setCreating(true);
    try {
      // La respuesta no se usa: se navega con el mandate_id generado aquí.
      await request<unknown>("/mandates", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (demo) onDemoCreated?.(mandateId);
      else onCreated(mandateId);
      return true;
    } catch (caught) {
      const reason = caught instanceof ApiError ? `El sistema respondió ${caught.status}.` : caught instanceof Error ? caught.message : null;
      setError(reason !== null ? `We couldn't create your permission: ${reason}` : "We couldn't create your permission. Check the connection to the system.");
      return false;
    } finally {
      setCreating(false);
    }
  }

  async function createMandate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await submitMandate();
  }

  function loadMartaDemoValues() {
    setHumanName((value) => value || DEMO_MARTA.name);
    setUserIdDoc((value) => value || DEMO_MARTA.document);
    setUserPhone((value) => value || DEMO_MARTA.phone);
    setUserEmail((value) => value || DEMO_MARTA.email);
    setMaxAmount((value) => value || DEMO_MARTA.amount);
    setMaxUses((value) => value || DEMO_MARTA.uses);
    setPriceBelow((value) => value || DEMO_MARTA.price);
    setCategory("travel.flights");
    setMerchant("mch_vuelaya");
    setFlightOrigin((value) => value || DEMO_MARTA.origin);
    setFlightDestination((value) => value || DEMO_MARTA.destination);
    setDepartureDate((value) => value || nearTermDate());
  }

  function clearWizardDemoPause() {
    if (demoPauseTimer.current !== null) window.clearTimeout(demoPauseTimer.current);
    demoPauseTimer.current = null;
    demoPauseResolver.current = null;
  }

  function waitForNarration(): Promise<void> {
    setWizardDemoStage("paused");
    return new Promise((resolve) => {
      const done = () => {
        clearWizardDemoPause();
        resolve();
      };
      demoPauseResolver.current = done;
      // El control es manual; este respaldo largo evita dejar una demo abandonada.
      demoPauseTimer.current = window.setTimeout(done, 15000);
    });
  }

  function advanceWizardDemo() {
    demoPauseResolver.current?.();
  }

  function cancelWizardDemo() {
    demoLogin.current?.reject(new DemoCancelledError("Demo cancelled."));
    demoLogin.current = null;
  }

  /** Espera a que la persona verifique el código a mano (demo sin AUTH_DEV_MODE). */
  function waitForManualSignIn(): Promise<AccessToken> {
    return new Promise((resolve, reject) => {
      demoLogin.current = { resolve, reject };
    });
  }

  async function runWizardDemo() {
    if (wizardDemoStage !== "idle" && wizardDemoStage !== "error") return;
    setError(null);
    setWizardDemoStage("preparing");

    try {
      try {
        await withTimeout(request<unknown>("/audit/reset", { method: "POST" }));
      } catch (caught) {
        if (caught instanceof ApiError) throw new Error("The audit session could not be reset.");
        throw caught;
      }
      loadMartaDemoValues();
      setCurrentStep(1);
      await waitForNarration();

      let verifiedEmail = isAuthenticated && session ? session.email : null;
      if (!verifiedEmail) {
        setWizardDemoStage("signin");
        const email = userEmail.trim() || DEMO_MARTA.email;
        setUserEmail(email);
        const started = await sendLoginCode(email);
        if (!started.ok) throw new Error(started.message);

        let token: AccessToken;
        if (started.value.codeDemo) {
          // AUTH_DEV_MODE=true: el backend devuelve el código y la demo lo usa sola.
          setLoginCode(started.value.codeDemo);
          const verified = await verifyLoginCode(email, started.value.codeDemo);
          if (!verified.ok) throw new Error(verified.message);
          token = verified.value;
        } else {
          // Sin modo desarrollo el código solo llega por correo: la persona lo ingresa.
          setWizardDemoStage("awaiting_code");
          token = await waitForManualSignIn();
        }
        verifiedEmail = token.email;
        await waitForNarration();
      }

      setCurrentStep(2);
      setWizardDemoStage("limits");
      await waitForNarration();

      setCurrentStep(3);
      setWizardDemoStage("authorizing");
      const created = await withTimeout(submitMandate(true, verifiedEmail));
      if (!created) throw new Error("The demonstration mandate could not be created.");
    } catch (caught) {
      clearWizardDemoPause();
      if (caught instanceof DemoCancelledError) {
        setWizardDemoStage("idle");
        return;
      }
      setWizardDemoStage("error");
      setError(caught instanceof Error ? caught.message : "The demo could not complete.");
    }
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (wizardDemoStage === "paused" && (event.key === " " || event.key === "ArrowRight")) {
        event.preventDefault();
        advanceWizardDemo();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [wizardDemoStage]);

  useEffect(() => {
    if (wizardDemoStage === "idle" || wizardDemoStage === "error") {
      setShowWizardDemoLabel(false);
      return;
    }
    setShowWizardDemoLabel(true);
    // Esperar el código es una acción de la persona: la etiqueta no se oculta.
    if (wizardDemoStage === "awaiting_code") return;
    const timer = window.setTimeout(() => setShowWizardDemoLabel(false), 4500);
    return () => window.clearTimeout(timer);
  }, [wizardDemoStage]);

  useEffect(() => () => {
    clearWizardDemoPause();
    demoLogin.current = null;
  }, []);

  const demoButton = wizardDemoStage === "paused"
    ? { label: "Continue demo →", onClick: advanceWizardDemo, disabled: false }
    : wizardDemoStage === "awaiting_code"
      ? { label: "Cancel demo", onClick: cancelWizardDemo, disabled: false }
      : { label: "▶ Start demo", onClick: () => void runWizardDemo(), disabled: wizardDemoStage !== "idle" && wizardDemoStage !== "error" };

  return (
    <main className="authorization-shell">
      <div className="starfield" aria-hidden="true" />
      <button className="wizard-demo-launch" type="button" onClick={demoButton.onClick} disabled={demoButton.disabled}>
        {demoButton.label}
      </button>
      <AnimatePresence>
        {showWizardDemoLabel && wizardDemoStage !== "idle" && wizardDemoStage !== "error" && (
          <motion.aside className="wizard-demo-action-label" key={wizardDemoStage} initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.22 }} aria-live="polite">
            <span>GUIDED DEMO · ACT 1</span><strong>{wizardDemoStage === "paused" ? "Presenter pause — press Space or → to continue." : WIZARD_DEMO_LABELS[wizardDemoStage]}</strong>
          </motion.aside>
        )}
      </AnimatePresence>

      <section className="authorization-layout">
        <div className="authorization-intro">
          <p className="mission-kicker">AGENTBUYER / YOUR PERMISSION, YOUR LIMITS</p>
          <h1>Authorize <span>Saturday</span></h1>
          <p>Your agent can help you buy, but you define every limit. Nothing happens outside this permission.</p>
          <div className="creator-saturday"><Saturday state="idle" expression={saturdayExpression} /></div>
          <div className="trust-note"><b>Your control comes first.</b><span>You can revoke this permission anytime.</span></div>
        </div>

        {/* noValidate: hay inputs required en pasos ocultos (display:none); la
            validación nativa bloqueaba el submit sin poder mostrar su burbuja.
            La validación real vive en createMandate, con errores visibles. */}
        <form className="mandate-form" onSubmit={createMandate} noValidate>
          <div className="form-heading"><p className="panel-eyebrow">NEW PERMISSION</p><h2>Give Saturday clear instructions</h2></div>
          <div className="wizard-progress" aria-label={`Step ${currentStep} of ${WIZARD_STEPS}`}>
            <span className={currentStep === 1 ? "is-current" : currentStep > 1 ? "is-complete" : ""}>1. Verify it's you</span>
            <span className={currentStep === 2 ? "is-current" : currentStep > 2 ? "is-complete" : ""}>2. Set the limits</span>
            <span className={currentStep === 3 ? "is-current" : ""}>3. Confirm</span>
          </div>

          <div className="wizard-step" style={{ display: currentStep === 2 ? "grid" : "none" }}>
            <h3>Set the limits</h3>
            <label>Who's authorizing?<input value={humanName} onChange={(event) => setHumanName(event.target.value)} placeholder="Your name" required /></label>
            <label>How much can it spend at most per purchase?<div className="money-field"><span>USD $</span><input value={maxAmount} onChange={(event) => setMaxAmount(event.target.value)} inputMode="decimal" placeholder="150" required /></div></label>
            <div className="form-pair">
              <label>What can it spend on?<select value={category} onChange={(event) => setCategory(event.target.value)}><option value="" disabled>Choose a category…</option>{categories.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
              <label>At which merchants?<select value={merchant} onChange={(event) => setMerchant(event.target.value)}><option value="" disabled>Choose a merchant…</option>{merchants.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select>{category.startsWith("travel.") && <small className="field-hint">Saturday searches real travel sites. If the best offer comes from a merchant outside your permission, it will ask you before buying — never silently.</small>}</label>
            </div>
            <div className="form-pair">
              <label>How many purchases at most?<input value={maxUses} onChange={(event) => setMaxUses(event.target.value)} inputMode="numeric" placeholder="3" required /></label>
              <label>Until when is this permission valid?<CalendarDatePicker value={validUntil} onChange={setValidUntil} ariaLabel="Pick how long the permission is valid" /></label>
            </div>
            <label>Any price condition?<div className="price-condition"><span>Only if the price drops below USD $</span><input value={priceBelow} onChange={(event) => setPriceBelow(event.target.value)} inputMode="decimal" placeholder="150" required /></div></label>
          </div>

          {category === "travel.flights" && currentStep === 2 && <div className="wizard-step flight-search-step">
            <div className="form-pair">
              <label>Origin<input value={flightOrigin} onChange={(event) => setFlightOrigin(event.target.value)} placeholder="BUE or Buenos Aires" required /></label>
              <label>Destination<input value={flightDestination} onChange={(event) => setFlightDestination(event.target.value)} placeholder="COR or Mexico City" required /></label>
            </div>
            <label>Departure date<CalendarDatePicker value={departureDate} onChange={setDepartureDate} ariaLabel="Pick the departure date" /></label>
          </div>}

          {category === "travel.hotels" && currentStep === 2 && <div className="wizard-step flight-search-step">
            <div className="form-pair">
              <label>Where will you stay?<input value={hotelDestination} onChange={(event) => setHotelDestination(event.target.value)} placeholder="Cordoba, Argentina" required /></label>
              <label>How many nights?<input value={hotelNights} onChange={(event) => setHotelNights(event.target.value)} inputMode="numeric" placeholder="3" required /></label>
            </div>
            <label>Check-in date<CalendarDatePicker value={hotelCheckIn} onChange={setHotelCheckIn} ariaLabel="Pick the check-in date" /></label>
            {hotelCheckIn && Number(hotelNights) > 0 && <small className="field-hint">Check-out: {readableDate(addDays(hotelCheckIn, Number(hotelNights)))} ({hotelNights} {Number(hotelNights) === 1 ? "night" : "nights"}).</small>}
          </div>}

          {currentStep === 1 && <div className="wizard-step wizard-security-step" style={{ background: "rgba(30, 41, 59, 0.6)", padding: "14px", borderRadius: "10px", border: "1px solid rgba(77, 124, 255, 0.35)", marginTop: "4px" }}>
            <h3>Verify it's you</h3>
            <p className="verify-subtitle">Add your contact details and sign in with a one-time code sent to your email.</p>
            <div className="verify-progress" role="status">
              <span>{completedVerificationCount} of 2 completed</span>
              <div className="verify-progress-bar" aria-hidden="true"><i style={{ width: `${Math.round((completedVerificationCount / 2) * 100)}%` }} /></div>
            </div>

            {/* a) Datos de contacto (no se verifican; viajan con el permiso) */}
            <section className={`verify-item is-${identityStatus}`}>
              <header className="verify-item-heading">
                <span className="verify-item-number" aria-hidden="true">{identityComplete ? "✓" : "1"}</span>
                <div className="verify-item-title"><b>Contact details</b><small>{identityComplete ? "Document and phone captured" : "Enter your ID document and phone"}</small></div>
                <em className={`verify-chip is-${identityStatus}`}>{verificationStatusLabel[identityStatus]}</em>
                {identityComplete && <button className="verify-edit" type="button" onClick={() => setEditingIdentity((editing) => !editing)}>{editingIdentity ? "Done" : "Edit"}</button>}
              </header>
              {!identityCollapsed && <div className="verify-item-body">
                <div className="form-pair">
                  <label>
                    ID document (ID / passport)
                    <input value={userIdDoc} onChange={(e) => setUserIdDoc(e.target.value)} onFocus={() => setSensitiveFieldFocused(true)} onBlur={() => setSensitiveFieldFocused(false)} placeholder="ID or passport number" />
                  </label>
                  <label>
                    Contact phone
                    <input value={userPhone} onChange={(e) => setUserPhone(e.target.value)} inputMode="tel" placeholder="+00 000 000 0000" />
                  </label>
                </div>
                {userPhone.trim() !== "" && !phoneComplete && (
                  <p className="verify-hint verify-hint-warn">Enter a complete phone number (at least 10 digits).</p>
                )}
              </div>}
            </section>

            {/* b) Inicio de sesión real: código de un solo uso por email */}
            <section className={`verify-item is-${signInStatus}`}>
              <header className="verify-item-heading">
                <span className="verify-item-number" aria-hidden="true">{isAuthenticated ? "✓" : "2"}</span>
                <div className="verify-item-title"><b>Email sign-in</b><small>{isAuthenticated && session ? `Signed in as ${session.email}` : codeSent ? `Code sent to ${emailHint || userEmail}` : "We'll email you a one-time code"}</small></div>
                <em className={`verify-chip is-${signInStatus}`}>{verificationStatusLabel[signInStatus]}</em>
                {isAuthenticated && <button className="verify-edit" type="button" onClick={signOut}>Use another email</button>}
              </header>
              {!isAuthenticated && <div className="verify-item-body">
                {/* El banner global puede cerrarse; aquí el aviso queda donde se actúa. */}
                {sessionNotice && <p className="verify-hint verify-hint-warn">{sessionNotice}</p>}
                <label>
                  Email (your receipt will be sent here)
                  <input value={userEmail} onChange={(e) => { setUserEmail(e.target.value); setCodeSent(false); setCodeDemo(null); }} onFocus={() => setSensitiveFieldFocused(true)} onBlur={() => setSensitiveFieldFocused(false)} type="email" inputMode="email" placeholder="you@example.com" disabled={sendingCode || verifyingCode} />
                </label>
                <button className="verify-action" type="button" onClick={() => void sendLoginCode()} disabled={sendingCode || verifyingCode || cooldownSeconds > 0 || !EMAIL_PATTERN.test(userEmail.trim())}>
                  {sendingCode ? "Sending…" : cooldownSeconds > 0 ? `Try again in ${cooldownSeconds}s` : codeSent ? "Send a new code" : "Send sign-in code"}
                </button>
                {codeSent && <>
                  <div className="otp-code-controls">
                    <input value={loginCode} onChange={(e) => setLoginCode(e.target.value.replace(/\D/g, "").slice(0, 6))} onFocus={() => setSensitiveFieldFocused(true)} onBlur={() => setSensitiveFieldFocused(false)} inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" aria-label="Sign-in code" />
                    <button className="verify-action verify-action-confirm" type="button" onClick={() => void verifyLoginCode()} disabled={verifyingCode || loginCode.length !== 6}>
                      {verifyingCode ? "Verifying…" : "Verify code"}
                    </button>
                  </div>
                  {codeDemo && (
                    <p className="verify-hint verify-hint-tip">
                      Development mode (AUTH_DEV_MODE): your code is <b>{codeDemo}</b>.{" "}
                      <button className="verify-edit" type="button" onClick={() => setLoginCode(codeDemo)}>Use it</button>
                    </p>
                  )}
                </>}
                {cooldownSeconds > 0 && <p className="verify-hint verify-hint-warn">Too many code requests. You can request a new code in {cooldownSeconds}s.</p>}
                {loginError && !(cooldownSeconds > 0 && loginError.startsWith("Too many code requests")) && <p className="verify-hint verify-hint-warn" role="alert">{loginError}</p>}
              </div>}
            </section>
          </div>}

          <div className="wizard-step" style={{ display: currentStep === 3 ? "grid" : "none" }}>
            <h3>Confirm and authorize</h3>
            <div className="permission-summary"><span>THIS IS WHAT YOUR PERMISSION WILL LOOK LIKE</span><p>{summary}</p></div>
          </div>

          {error && <div className="form-error" role="alert">{error}</div>}

          {currentStep === 1 && !stepOneReady && <p className="wizard-notice">To continue, add your contact details and sign in with the code sent to your email.</p>}

          <div className="wizard-navigation">
            {currentStep > 1 && <button className="wizard-back" type="button" onClick={() => setCurrentStep((currentStep - 1) as WizardStep)}>← Back</button>}
            {currentStep === 1 && <button className="wizard-next" type="button" disabled={!stepOneReady} onClick={() => setCurrentStep(2)}>Next →</button>}
            {currentStep === 2 && <button className="wizard-next" type="button" onClick={() => setCurrentStep(3)}>Next →</button>}
            {currentStep === 3 && <button className="authorize-button" disabled={creating || !isAuthenticated} type="submit">{creating ? "CREATING YOUR PERMISSION…" : !isAuthenticated ? "⚠ SIGN IN REQUIRED" : "AUTHORIZE SATURDAY"}</button>}
          </div>
        </form>
      </section>
    </main>
  );
}
