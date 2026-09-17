/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** URL base del backend (FastAPI). Default: http://127.0.0.1:8000 */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
