# 🎤 AgentBuyer Presentation: Pitch & Technical Defense

> **Challenge:** MODULE 05 // RETOS · 01 — El comprador que no es humano  
> **Team:** AgentBuyer  
> **Repository:** https://github.com/anapaolaoviedo/AgentBuyer  

---

## Slide 1: The Non-Human Buyer Dilemma

### Visual
- Headline: **When the Buyer is an AI Agent, Every Payment Assumption Breaks Down**
- Visual comparison:
  - *Past:* Human clicks "Pay" $\rightarrow$ 3DS / OTP verification $\rightarrow$ Cardholder liability.
  - *Present & Future:* AI Agent discovers, decides, and executes transactions autonomously.
- The Core Conflict:
  - Merchants either **block all bots** (losing billions in automated sales) or **treat them as humans** (absorbing massive chargeback fraud).
  - Humans refuse to hand over raw credit card numbers to autonomous models.

### Speaker Script (30 seconds)
> *"Every payment system in the world was designed for a human sitting behind a screen. But today, AI agents are booking flights, restocking inventories, and buying subscriptions. How does a merchant know an agent is genuinely authorized? How does a user delegate spending power without handing over their raw card? And what happens when an agent hallucinates? Today, we introduce AgentBuyer: the missing cryptographic mandate protocol for autonomous commerce."*

---

## Slide 2: The 4-Party Cryptographic Mandate Circuit

### Visual
- Protocol Diagram:
  1. **Human (Marta)** signs an Ed25519 Purchase Mandate bound to a Scoped Virtual Payment Token.
  2. **AI Purchasing Agent** monitors the market, selects deals matching conditions, and constructs signed purchase attempts with nonces.
  3. **Merchant (VuelaYa)** runs a 6-Stage independent verification protocol (verifying human signature, agent identity, live registry status, and AST constraints).
  4. **Cryptographic Merkle Ledger** logs an immutable, tamper-evident hash chain for real-time auditability.

### Speaker Script (45 seconds)
> *"AgentBuyer establishes a 4-party circuit. First, the human creates a purchase mandate: setting max spend, monthly budgets, and condition rules like 'price <= 150 AND destination == COR'. Crucially, the human never shares their raw card: the mandate issues a cryptographically scoped virtual token. When the agent buys, the merchant verifies both signatures and checks the authoritative registry in real time before settling."*

---

## Slide 3: The Trial by Fire — Live Revocation & Ugly Cases

### Visual
- Live Demonstration Flow:
  - ✅ **Flight \$130 (Within Mandate):** Instant approval, payment token settled, receipt generated.
  - ⚠️ **Flight \$300 (Outside Mandate):** Escapes silent overspending $\rightarrow$ Escalates to Human-In-The-Loop (HITL) with 1-click cryptographic approval.
  - 🚨 **Live Revocation (Trial by Fire):** Marta clicks 'Revoke' $\rightarrow$ Registry updates live $\rightarrow$ Next attempt fails synchronously (zero caching).
  - 🛡️ **Adversarial Defense:** 8/8 attack vectors blocked (replay, price tampering, category hopping, signature forgery, AST injection).

### Speaker Script (45 seconds)
> *"We built AgentBuyer for the ugly cases. What if a flight costs \$300 instead of \$150? It is never silently approved; it escalates to Marta for Human-In-The-Loop authorization. And in the ultimate Trial by Fire: if Marta revokes her mandate live on stage, the very next purchase attempt fails in milliseconds at the merchant verification layer. No caching, no delay, zero risk."*

---

## Slide 4: Dispute Resolution & The Immutable Audit Trail

### Visual
- Split-screen comparison of Role-Based Audit Views:
  - *Human View:* Clean receipts, transparent active delegations.
  - *Merchant View:* Cryptographic proof of authorization and compliance tokens.
  - *Auditor View:* SHA-256 Merkle hash chain + automated mathematical chargeback arbiter.
- Verdict Rules Table:
  - Forged Mandate $\rightarrow$ Fraudster liable, cardholder protected.
  - Post-Revocation Tx $\rightarrow$ Merchant liable.
  - Out-of-mandate unapproved $\rightarrow$ Agent liable.
  - Compliant purchase $\rightarrow$ Human liable (Chargeback dismissed).

### Speaker Script (30 seconds)
> *"When a cardholder denies a charge, banks usually take 60 days of subjective back-and-forth. AgentBuyer resolves disputes in under a second. Our automated arbiter replays the SHA-256 hash chain and cryptographic signatures to deterministically rule liability. If the agent bought within Marta's valid mandate, the merchant is protected; if the merchant accepted a post-revocation attempt, the cardholder is refunded immediately."*

---

## Slide 5: Business Impact & Technical Superiority

### Visual
- Key Metrics:
  - **100%** Protection against raw card theft (Scoped tokenization).
  - **< 1ms** Verification latency (Ed25519 + AST parser).
  - **8/8** Adversarial attacks defeated.
  - **\$0** Merchant chargeback liability on compliant transactions.

### Speaker Script (30 seconds)
> *"AgentBuyer unlocks the future of autonomous agent commerce. Merchants can welcome AI buyers with open arms, knowing fraud is mathematically impossible. Humans can unleash their agents with total peace of mind. Thank you, and we welcome your live trial-by-fire tests!"*
