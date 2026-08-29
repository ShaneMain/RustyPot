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

/**
 * Cloudflare exposes the visitor's country on `request.cf`, NOT as a request
 * header — `cf-ipcountry` only reaches an origin if the "Add visitor location
 * headers" Managed Transform is enabled. It was not, so RustyPot's
 * `cf_ipcountry` column was NULL on every row ever recorded and every geo panel
 * was structurally empty rather than merely sparse. Forward it explicitly.
 */
function withGeoHeaders(request) {
  const headers = new Headers(request.headers);
  const cf = request.cf;
  if (cf?.country) headers.set("cf-ipcountry", cf.country);
  if (cf?.asn) headers.set("cf-asn", String(cf.asn));
  if (cf?.asOrganization) headers.set("cf-as-org", cf.asOrganization);
  return headers;
}

/**
 * Strip the hosting platform's fingerprints from honeypot responses.
 *
 * Cloud Run stamps `x-cloud-trace-context` on every response and it survives
 * all the way to the client — a Google Cloud tell on what is meant to look like
 * a PHP host. The container cannot remove it; the header is added downstream of
 * it, so the strip has to happen here.
 *
 * `server` is deliberately NOT rewritten. Cloudflare already replaces whatever
 * the origin sent with `server: cloudflare`, which is what every
 * Cloudflare-fronted site returns and therefore reveals nothing. Setting it to
 * a fake nginx here would be overwritten anyway, and a value that disagreed
 * with the rest of the CF response set would be more conspicuous than the
 * default.
 */
function disguiseOrigin(upstream) {
  const headers = new Headers(upstream.headers);
  headers.delete("x-cloud-trace-context");
  headers.delete("alt-svc");
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const hasBody = request.method !== "GET" && request.method !== "HEAD";

    if (isHoneypotPath(url.pathname)) {
      const target = new URL(url.pathname + url.search, env.HONEYPOT_BACKEND);
      const upstream = await fetch(target, {
        method: request.method,
        headers: withGeoHeaders(request),
        body: hasBody ? request.body : undefined,
        redirect: "manual",
      });
      return disguiseOrigin(upstream);
    }

    const appTarget = new URL(url.pathname + url.search, env.APP_BACKEND);
    return fetch(appTarget, {
      method: request.method,
      headers: request.headers,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
    });
  },
};
