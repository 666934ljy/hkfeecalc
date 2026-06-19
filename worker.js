/**
 * Cloudflare Worker — Security Headers Injector for hkfeecalc.com
 * 
 * Deploy: npx wrangler deploy
 * Route:   hkfeecalc.com/*
 *
 * This worker acts as a transparent proxy that adds security headers
 * to every response from GitHub Pages, fixing the F grade on securityheaders.com
 */

export default {
  async fetch(request, env, ctx) {
    // Fetch the original response from GitHub Pages
    const response = await fetch(request);

    // Clone it so we can add headers
    const newHeaders = new Headers(response.headers);

    // --- Security Headers ---

    // HSTS: force HTTPS for 1 year, include subdomains
    newHeaders.set(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );

    // CSP: allow same-origin scripts/styles, block everything else
    newHeaders.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    );

    // Block clickjacking
    newHeaders.set("X-Frame-Options", "DENY");

    // Prevent MIME sniffing
    newHeaders.set("X-Content-Type-Options", "nosniff");

    // Don't leak referrer to external sites
    newHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");

    // Restrict browser features
    newHeaders.set(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    );

    // Override the overly-broad CORS header from GitHub Pages
    newHeaders.set("Access-Control-Allow-Origin", "https://hkfeecalc.com");

    // --- Performance ---
    // Cache static assets aggressively (30 days)
    const url = new URL(request.url);
    if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf)$/i.test(url.pathname)) {
      newHeaders.set("Cache-Control", "public, max-age=2592000, immutable");
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  },
};
