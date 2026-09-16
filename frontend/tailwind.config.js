/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        space: "#0A0E1A",
        panel: "#141B2E",
        border: "#232D45",
        brand: "#4D7CFF",
        approve: "#3DDC97",
        escalate: "#FFB84D",
        reject: "#FF5C5C",
        ink: "#E8ECF5",
        muted: "#8A94AD"
      },
      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
        body: ["Inter", "sans-serif"]
      }
    }
  },
  plugins: []
};
