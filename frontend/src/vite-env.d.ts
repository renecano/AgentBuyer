/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** URL base del backend (FastAPI). Default: http://127.0.0.1:8000 */
  readonly VITE_API_BASE?: string;
  /** Clave pública de Stripe (opcional; usada por el flujo de tokenización actual). */
  readonly VITE_STRIPE_PUBLISHABLE_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
