// Where the Lovable Squares server (the /api folder, a Cloudflare Worker) lives.
// Local testing: run `npm run dev` in /api and serve this folder on port 8901.
window.LS_API = /^(localhost|127\.0\.0\.1)$/.test(location.hostname)
  ? "http://localhost:8787"
  : "https://lovable-squares-api.SUBDOMAIN.workers.dev";
