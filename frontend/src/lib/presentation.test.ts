import { describe, expect, it } from "vitest";
import { checkDetailLabel, localizedText, mandateStatusLabel } from "./presentation";

describe("presentation (7.3)", () => {
  it("labels every live status, including paused and expired (they used to show LOADING)", () => {
    expect(mandateStatusLabel("active")).toBe("ACTIVE");
    expect(mandateStatusLabel("paused")).toBe("PAUSED");
    expect(mandateStatusLabel("revoked")).toBe("REVOKED");
    expect(mandateStatusLabel("expired")).toBe("EXPIRED");
    expect(mandateStatusLabel("loading")).toBe("LOADING");
  });

  it("reads the engine's English check details", () => {
    expect(checkDetailLabel("category", "travel.flights allowed")).toBe("Flights allowed");
    expect(checkDetailLabel("category", "travel.hotels is not in ['travel.flights']")).toBe("Hotels is not an allowed category");
    expect(checkDetailLabel("merchant", "mch_vuelaya allowed")).toBe("VuelaYa authorized");
    expect(checkDetailLabel("merchant", "mch_other is not in ['mch_vuelaya']")).toBe("Other is not an authorized merchant");
  });

  it("passes backend text through untouched, only naming identifiers and verdicts", () => {
    expect(localizedText("Purchase rejected: the mandate is revoked.")).toBe("Purchase rejected: the mandate is revoked.");
    expect(localizedText("Chose a flight from mch_vuelaya")).toBe("Chose a flight from VuelaYa");
  });
});
