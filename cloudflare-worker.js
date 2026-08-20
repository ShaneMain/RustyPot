/**
 * Cloudflare Worker — path-based routing for RustyPot.
 *
 * Exploit-path prefixes route to the RustyPot honeypot container; everything
 * else routes to the real app. The attacker sees the same hostname — the split
 * is invisible.
 *
 * Deploy via: wrangler deploy
 * Set secrets: HONEYPOT_BACKEND (the honeypot container URL), APP_BACKEND (your app URL).
 *
 * If you disabled trap families in RustyPot (ENABLED_TRAPS), trim the matching
 * patterns here too — paths routed here that RustyPot doesn't trap return 404.
 */

const HONEYPOT_PREFIXES = /^\/(wp-|\.env|\.git|\.svn|\.hg|\.aws|\.ssh|xmlrpc|phpinfo|readme\.html|index\.php|shell\.php|c99\.php|r57\.php|webshell\.php|adminer\.php|user\/login|administrator|admin\/login|actuator|_ignition|pma|dbadmin|sqlmanager|phpmyadmin|phpMyAdmin|solr|server-status|server-info)/i;

// Subdirectory sweeps: /core/.env, /web/.env.dev, /.envrc anywhere in the path,
// plus non-dotfile env names like /config.env. Matches the server-side rule in
// handlers.rs is_env_variant.
const ENV_ANYWHERE = /\/\.env|\/[^/]+\.env$/i;

function isHoneypotPath(pathname) {
  return HONEYPOT_PREFIXES.test(pathname) || ENV_ANYWHERE.test(pathname);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (isHoneypotPath(url.pathname)) {
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
