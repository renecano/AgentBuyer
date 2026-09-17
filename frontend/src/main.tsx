import { createRoot } from "react-dom/client";
import App from "./App";
import SessionBanner from "./components/SessionBanner";
import { AuthProvider } from "./lib/AuthProvider";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <AuthProvider>
    {/* Fuera de <App/>: el aviso de sesión caída no depende de la vista activa. */}
    <SessionBanner />
    <App />
  </AuthProvider>,
);
