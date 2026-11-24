// Minimal 1.5px stroke icon set drawn for the console (no icon-font dependency).
const P = {
  scan: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l7-7",
  tools: "M4 6h10M4 12h16M4 18h7M17 4v4M14 16v4",
  overview: "M4 13h6V4H4zM14 20h6v-9h-6zM4 20h6v-3H4zM14 7h6V4h-6z",
  inventory: "M4 5h16M4 10h16M4 15h16M4 20h10",
  subdomains: "M6 4v16M6 8h6M6 14h6M12 8h6M12 14h4M6 20h10",
  ports: "M5 7h4v4H5zM15 7h4v4h-4zM9 9h6M7 11v6h10v-6",
  tech: "M8 4 3 12l5 8M16 4l5 8-5 8M13 5l-2 14",
  api: "M7 8 3 12l4 4M17 8l4 4-4 4M14 6l-4 12",
  shield: "M12 3 4 6v6c0 4.5 3.4 8.2 8 9 4.6-.8 8-4.5 8-9V6z M9 12l2 2 4-4",
  infra: "M4 18h16M6 18V9l6-4 6 4v9M10 18v-5h4v5",
  priority: "M5 20V4M5 5h11l-2 4 2 4H5",
  changes: "M4 17 9 11l4 4 7-9M15 6h5v5",
  graph: "M6 7a2 2 0 1 0 0-.01M18 5a2 2 0 1 0 0-.01M17 18a2 2 0 1 0 0-.01M8 7l8-1M7.5 8.5l8 8",
  ai: "M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M18 6l-2.5 2.5M8.5 15.5 6 18",
  history: "M4 12a8 8 0 1 0 2.3-5.6M4 4v4h4M12 8v4l3 2",
  coverage: "M12 3a9 9 0 1 0 9 9h-9z M14 3.3A9 9 0 0 1 20.7 10H14z",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  play: "M7 5v14l11-7z",
  live: "M4 12h3l2-6 4 12 2-6h5",
  lock: "M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z",
  unlock: "M7 11V8a5 5 0 0 1 9.6-2M5 11h14v10H5z",
  plus: "M12 5v14M5 12h14",
  stop: "M7 7h10v10H7z",
  download: "M12 4v11M7 10l5 5 5-5M5 20h14",
  install: "M12 3v10M8 9l4 4 4-4M4 15v4h16v-4",
  home: "M4 11 12 4l8 7M6 9.5V20h12V9.5",
  fit: "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5",
  terminal: "M4 5h16v14H4zM7.5 9.5 10 12l-2.5 2.5M12 15h4.5",
  module: "M12 3 4 7.5v9L12 21l8-4.5v-9zM4 7.5 12 12l8-4.5M12 12v9",
  zip: "M6 3h9l4 4v14H6zM11 5h2M11 8h2M11 11h2M10.5 14h3v3h-3z",
  image: "M4 5h16v14H4zM4 15l4.5-4.5L13 15l2.5-2.5L20 17M15.5 9.5a1 1 0 1 0 0-.01",
  folder: "M3 6.5h6l2 2h10V19H3zM3 6.5V5h6l2 1.5",
  key: "M14.5 9.5a4 4 0 1 0-1.2 2.8L20 19v2h-2v-1.5h-1.5V18H15l-1.7-1.7M8.5 8.5h.01",
  triage: "M4 6h16M4 12h10M4 18h6M17 14l2 2 3-4",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4",
  focus: "M12 12m-3 0a3 3 0 1 0 6 0 3 3 0 1 0-6 0M12 3v3M12 18v3M3 12h3M18 12h3",
};

export default function Icon({ name, size = 16, className = "" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
         strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={P[name] || P.overview} />
    </svg>
  );
}
