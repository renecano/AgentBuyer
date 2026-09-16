import { motion } from "framer-motion";

export type SaturdayState = "idle" | "thinking" | "approve" | "escalate" | "reject";
export type SaturdayExpression = "covering" | "happy" | "nodding" | "ready";

type SaturdayProps = {
  state: SaturdayState;
  expression?: SaturdayExpression;
};

const stateCopy: Record<SaturdayState, string> = {
  idle: "SATURDAY · STANDING BY",
  thinking: "SATURDAY · ANALYZING",
  approve: "SATURDAY · AUTHORIZED",
  escalate: "SATURDAY · NEEDS HUMAN",
  reject: "SATURDAY · BLOCKED",
};

const palette: Record<SaturdayState, string> = {
  idle: "#4D7CFF",
  thinking: "#4D7CFF",
  approve: "#3DDC97",
  escalate: "#FFB84D",
  reject: "#FF5C5C",
};

export default function Saturday({ state, expression }: SaturdayProps) {
  const isFrozen = state === "reject";
  const isThinking = state === "thinking";
  const isCovering = expression === "covering";

  const cardMotion = {
    idle: { y: [0, -10, 0], rotate: 0, scale: 1 },
    thinking: { y: [0, -4, 0], rotate: [-2, 2, -2], scale: 1 },
    approve: { y: [0, -15, 0], rotate: 0, scale: [1, 1.045, 1] },
    escalate: { y: [0, -3, 0], rotate: [-1, 1, -1], scale: 1 },
    reject: { y: 0, rotate: 0, scale: 0.98 },
  };

  const transition = {
    idle: { duration: 3.2, repeat: Infinity, ease: "easeInOut" },
    thinking: { duration: 1.25, repeat: Infinity, ease: "easeInOut" },
    approve: { duration: 0.72, ease: "easeOut" },
    escalate: { duration: 0.8, repeat: Infinity, ease: "easeInOut" },
    reject: { duration: 0.45, ease: "easeOut" },
  };
  const cardAnimation = expression === "nodding"
    ? { y: [0, 7, 0], rotate: 0, scale: 1 }
    : cardMotion[state];
  const cardTransition = expression === "nodding"
    ? { duration: 0.5, ease: "easeInOut" }
    : transition[state];
  const leftEyeAnimation = isCovering
    ? { opacity: 1, scaleY: 0.08 }
    : expression === "happy"
      ? { scaleY: [1, 0.08, 1], rotate: [0, -8, 0] }
      : isThinking ? { x: [-4, 4, -4], scaleY: [1, 0.92, 1] } : { scaleY: [1, 0.08, 1] };
  const rightEyeAnimation = isCovering
    ? { opacity: 1, scaleY: 0.08 }
    : isThinking ? { x: [4, -4, 4], scaleY: [1, 0.92, 1] } : { scaleY: [1, 0.08, 1] };
  const eyeTransition = expression === "happy"
    ? { duration: 0.5, ease: "easeInOut" }
    : isThinking ? { duration: 0.8, repeat: Infinity } : { duration: 4.2, repeat: Infinity, repeatDelay: 1.8 };

  return (
    <div className={`saturday-wrap saturday-${state}`} aria-label={`Saturday: ${stateCopy[state]}`}>
      <motion.div
        className="saturday-aura"
        animate={{ opacity: state === "idle" ? [0.32, 0.65, 0.32] : state === "reject" ? 0.45 : [0.35, 0.8, 0.35], scale: state === "approve" ? [1, 1.3, 1] : [1, 1.12, 1] }}
        transition={{ duration: state === "approve" ? 0.75 : 1.8, repeat: state === "reject" ? 0 : Infinity, ease: "easeInOut" }}
        style={{ backgroundColor: palette[state] }}
      />
      <motion.article
        className="saturday-card"
        animate={cardAnimation}
        transition={cardTransition}
        style={{ "--state-glow": palette[state] } as React.CSSProperties}
      >
        <div className="card-topline">
          <div className="card-brand" aria-label="yuno por nauta, AgentBuyer">
            <span className="card-brand-primary">yuno <b>×</b> nauta</span>
            <span className="card-brand-secondary">AGENTBUYER</span>
          </div>
          <span className="card-status">{stateCopy[state]}</span>
        </div>

        <div className={`face ${expression ? `face-${expression}` : ""}`}>
          {state === "escalate" && <span className="brow brow-left" />}
          <motion.span
            className="eye"
            animate={leftEyeAnimation}
            transition={eyeTransition}
          />
          <motion.span
            className="eye"
            animate={rightEyeAnimation}
            transition={eyeTransition}
          />
          {state === "escalate" && <span className="brow brow-right" />}
          <span className={`mouth mouth-${state} ${expression === "happy" || expression === "ready" ? "mouth-happy" : ""}`} />
        </div>

        <div className="card-bottom">
          <div className="chip" aria-hidden="true"><i /><i /><i /></div>
          <span className="microprint">nextwave 2026</span>
        </div>

        {isThinking && <motion.div className="scan-line" animate={{ y: [-80, 105] }} transition={{ duration: 1.45, repeat: Infinity, ease: "linear" }} />}
        {state === "approve" && <motion.div className="approve-spark" animate={{ opacity: [0, 1, 0], scale: [0.5, 1.2, 1.6] }} transition={{ duration: 0.7 }} />}
        {isFrozen && <div className="freeze-overlay"><span className="lock">⌑</span><svg viewBox="0 0 330 190" aria-hidden="true"><path d="M228 3 206 55l19 24-42 35 25 30-38 43" /></svg></div>}
      </motion.article>
    </div>
  );
}
