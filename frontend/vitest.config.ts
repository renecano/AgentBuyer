import { defineConfig } from "vitest/config";

// Tests unitarios de la lógica sin UI (canonicalización, y en los siguientes pasos
// el almacén de llaves). Corren en Node: trae WebCrypto con Ed25519 nativo, y
// fake-indexeddb (src/test/setup.ts) pone un IndexedDB en memoria.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    setupFiles: ["./src/test/setup.ts"],
  },
});
