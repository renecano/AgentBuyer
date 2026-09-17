/**
 * Sesión de autenticación en memoria: { token, email, role, expiresAt }.
 *
 * - Solo en memoria (no localStorage/sessionStorage): recargar la página cierra la sesión.
 * - Registra el token en el cliente HTTP (lib/api), así las llamadas lo envían
 *   mientras la sesión esté vigente.
 * - Todavía no hay UI de login que lo use ni manejador de 401 conectado.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { setTokenGetter } from "./api";
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

type AuthContextValue = {
  session: AuthSession | null;
  /** Hay sesión y no expiró (evaluado en el render). */
  isAuthenticated: boolean;
  startEmailLogin: (email: string) => Promise<EmailLoginStart>;
  /** Verifica el código, guarda la sesión y devuelve el token emitido. */
  verifyEmailLogin: (email: string, code: string) => Promise<AccessToken>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

function isActive(session: AuthSession | null): session is AuthSession {
  return session !== null && session.expiresAt > Date.now();
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  // Ref para que el getter del cliente HTTP lea siempre la sesión vigente, incluso
  // en llamadas hechas justo después de verificar (antes del siguiente render).
  const sessionRef = useRef<AuthSession | null>(null);

  const updateSession = useCallback((next: AuthSession | null) => {
    sessionRef.current = next;
    setSession(next);
  }, []);

  useEffect(
    () => setTokenGetter(() => (isActive(sessionRef.current) ? sessionRef.current.token : null)),
    [],
  );

  const startEmailLogin = useCallback((email: string) => requestEmailCode(email), []);

  const verifyEmailLogin = useCallback(async (email: string, code: string) => {
    const token = await requestEmailVerification(email, code);
    updateSession({
      token: token.accessToken,
      email: token.email,
      role: token.role,
      expiresAt: Date.now() + token.expiresIn * 1000,
    });
    return token;
  }, [updateSession]);

  const logout = useCallback(() => updateSession(null), [updateSession]);

  const value = useMemo<AuthContextValue>(() => ({
    session,
    isAuthenticated: isActive(session),
    startEmailLogin,
    verifyEmailLogin,
    logout,
  }), [session, startEmailLogin, verifyEmailLogin, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>.");
  return context;
}
