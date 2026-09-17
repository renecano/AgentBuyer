/**
 * Sesión de autenticación en memoria: { token, email, role, expiresAt }.
 *
 * - Solo en memoria (no localStorage/sessionStorage): recargar la página cierra la sesión.
 * - Registra el token en el cliente HTTP (lib/api), así las llamadas lo envían
 *   mientras la sesión esté vigente.
 * - Caída de sesión, por dos caminos que terminan igual (sesión limpia + aviso):
 *     1) proactivo: el token expiró (o le queda menos que EXPIRY_SKEW_MS) → se
 *        trata como no autenticado ANTES de llamar al backend.
 *     2) reactivo: una petición que SÍ llevaba token recibió un 401 (token
 *        inválido, o el backend reinició con otro JWT_SECRET).
 *   Los endpoints de login van con skipAuth, así que su 401 ("código incorrecto")
 *   nunca llega aquí: lib/api solo avisa cuando la petición llevaba token.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { setTokenGetter, setUnauthorizedHandler } from "./api";
import {
  startEmailLogin as requestEmailCode,
  verifyEmailLogin as requestEmailVerification,
  type AccessToken,
  type AuthRole,
  type EmailLoginStart,
} from "./authApi";

export type AuthSession = {
  token: string;
  email: string;
  role: AuthRole;
  /** Epoch en milisegundos. */
  expiresAt: number;
};

/** Margen antes del vencimiento real: no se usa un token a punto de expirar. */
const EXPIRY_SKEW_MS = 15_000;

export const SESSION_EXPIRED_MESSAGE = "Your session expired. Sign in again with a new email code.";

type AuthContextValue = {
  session: AuthSession | null;
  /** Hay sesión y le queda margen suficiente (evaluado en el render). */
  isAuthenticated: boolean;
  /** Aviso a mostrar cuando la sesión se cayó sola (no al cerrar sesión a mano). */
  sessionNotice: string | null;
  dismissSessionNotice: () => void;
  startEmailLogin: (email: string) => Promise<EmailLoginStart>;
  /** Verifica el código, guarda la sesión y devuelve el token emitido. */
  verifyEmailLogin: (email: string, code: string) => Promise<AccessToken>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

function isActive(session: AuthSession | null): session is AuthSession {
  return session !== null && session.expiresAt - EXPIRY_SKEW_MS > Date.now();
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);
  // Ref para que el getter del cliente HTTP lea siempre la sesión vigente, incluso
  // en llamadas hechas justo después de verificar (antes del siguiente render).
  const sessionRef = useRef<AuthSession | null>(null);

  const updateSession = useCallback((next: AuthSession | null) => {
    sessionRef.current = next;
    setSession(next);
  }, []);

  /** Cierra la sesión caída. Idempotente: varias llamadas seguidas avisan una vez. */
  const expireSession = useCallback(() => {
    if (sessionRef.current === null) return;
    updateSession(null);
    setSessionNotice(SESSION_EXPIRED_MESSAGE);
  }, [updateSession]);

  // El getter es también el punto de expiración proactiva: si la sesión ya no
  // sirve, la llamada sale sin token Y la UI se entera en el acto (sin esperar
  // un 401 que hoy ni siquiera llegaría, porque /mandates aún es anónimo).
  useEffect(() => setTokenGetter(() => {
    const current = sessionRef.current;
    if (current === null) return null;
    if (isActive(current)) return current.token;
    expireSession();
    return null;
  }), [expireSession]);

  useEffect(() => setUnauthorizedHandler(() => expireSession()), [expireSession]);

  // Expiración proactiva sin interacción: al vencer el plazo la UI cambia sola,
  // en vez de esperar a que la persona haga clic en algo que ya no funciona.
  useEffect(() => {
    if (session === null) return undefined;
    const delay = session.expiresAt - EXPIRY_SKEW_MS - Date.now();
    if (delay <= 0) {
      expireSession();
      return undefined;
    }
    const timer = window.setTimeout(expireSession, delay);
    return () => window.clearTimeout(timer);
  }, [session, expireSession]);

  const dismissSessionNotice = useCallback(() => setSessionNotice(null), []);

  const startEmailLogin = useCallback((email: string) => requestEmailCode(email), []);

  const verifyEmailLogin = useCallback(async (email: string, code: string) => {
    const token = await requestEmailVerification(email, code);
    updateSession({
      token: token.accessToken,
      email: token.email,
      role: token.role,
      expiresAt: Date.now() + token.expiresIn * 1000,
    });
    setSessionNotice(null);
    return token;
  }, [updateSession]);

  // Cerrar sesión a mano es una decisión de la persona: no lleva aviso.
  const logout = useCallback(() => {
    updateSession(null);
    setSessionNotice(null);
  }, [updateSession]);

  const value = useMemo<AuthContextValue>(() => ({
    session,
    isAuthenticated: isActive(session),
    sessionNotice,
    dismissSessionNotice,
    startEmailLogin,
    verifyEmailLogin,
    logout,
  }), [session, sessionNotice, dismissSessionNotice, startEmailLogin, verifyEmailLogin, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>.");
  return context;
}
