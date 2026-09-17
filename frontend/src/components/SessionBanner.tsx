/**
 * Aviso de sesión caída, visible en cualquier vista (Mission Control, compras,
 * auditoría o el wizard): la sesión vive fuera del wizard, así que el aviso
 * también. Solo aparece cuando la sesión se cayó sola — al cerrar sesión a mano
 * no hay nada que avisar.
 */
import { AnimatePresence, motion } from "framer-motion";
import { useAuth } from "../lib/AuthProvider";

export default function SessionBanner() {
  const { sessionNotice, dismissSessionNotice } = useAuth();

  return (
    <AnimatePresence>
      {sessionNotice && (
        <motion.div
          className="session-banner"
          role="alert"
          aria-live="assertive"
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -12 }}
          transition={{ duration: 0.2 }}
        >
          <span aria-hidden="true">🔒</span>
          <p>{sessionNotice}</p>
          <button type="button" onClick={dismissSessionNotice} aria-label="Dismiss notice">✕</button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
