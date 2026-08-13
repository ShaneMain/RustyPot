/**
 * Cloudflare Worker — path-based routing for RustyPot.
 *
 * Exploit-path prefixes route to the RustyPot honeypot container; everything
 * else routes to the real app. The attacker sees the same hostname — the split
 * is invisible.
 *
 * Deploy via: wrangler deploy
 * Set secrets: HONEYPOT_BACKEND (the honeypot container URL), APP_BACKEND (your app URL).
 */

const HONEYPOT_PATHS = /^\/(wp-|\.env|\.git|xmlrpc|phpinfo|index\.php)/i;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (HONEYPOT_PATHS.test(url.pathname)) {
      const target = new URL(url.pathname + url.search, env.HONEYPOT_BACKEND);
      return fetch(target, {
        method: request.method,
        headers: request.headers,
        body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
        redirect: "manual",
      });
    }

    const appTarget = new URL(url.pathname + url.search, env.APP_BACKEND);
    return fetch(appTarget, {
      method: request.method,
      headers: request.headers,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
      redirect: "manual",
    });
  },
};
