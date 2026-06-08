/**
 * runner.js — Playwright TLS probe
 *
 * For each domain in DOMAINS_FILE, opens an HTTPS connection through a given
 * SOCKS proxy, records the HTTP status, and writes results to a JSON file.
 *
 * Usage:
 *   node tls-probe.js <proxy-name> <proxy-server> [tls-version] [post-quantum]
 *
 * Arguments:
 *   proxy-name    Short label written into every result record (e.g. "gost")
 *   proxy-server  SOCKS5 URL (e.g. "socks5://127.0.0.1:1080")
 *   tls-version   "1.2" or "1.3" (default: "1.3")
 *   post-quantum  "on" or "off" — enables ML-KEM/Kyber in TLS 1.3 (default: "on")
 *
 * Environment:
 *   DOMAINS_FILE  Path to newline-separated domain list (default: ./domains.txt)
 *
 * Output:
 *   results/results.<proxy-name>.json
 */

import { firefox } from "playwright";
import fs from "node:fs/promises";

const DOMAINS_FILE = process.env.DOMAINS_FILE ?? "./domains.txt";

const PROXY_NAME   = process.argv[2];
const PROXY_SERVER = process.argv[3];
const TLS_VERSION  = process.argv[4] ?? "1.3";
const POST_QUANTUM = process.argv[5] ?? "on";

if (!PROXY_NAME || !PROXY_SERVER) {
  console.error("Usage: node runner.mjs <proxy-name> <proxy-server> [tls-version] [post-quantum]");
  console.error('Example: node runner.mjs sslocal "socks5://127.0.0.1:1080" 1.3 on');
  console.error('         node runner.mjs sslocal "socks5://127.0.0.1:1080" 1.2');
  process.exit(2);
}

const POST_QUANTUM_EFFECTIVE = TLS_VERSION === "1.3" ? POST_QUANTUM : "n/a";
const OUT_JSON     = `results/results.${PROXY_NAME}.json`;
const NAV_TIMEOUT  = 15_000; // ms per page navigation
const BATCH_SIZE   = 250;    // domains per browser instance (limits memory growth)

/**
 * Returns the firefox about:config overrides for the requested TLS mode.
 * HTTP/3 is disabled so all traffic goes through the SOCKS proxy reliably.
 *
 * @returns {Record<string, boolean | number>}
 */
function buildFirefoxPrefs() {
  return {
    "security.tls.version.min":    1,
    "security.tls.version.max":    TLS_VERSION === "1.2" ? 3 : 4,
    "security.tls.enable_kyber":   POST_QUANTUM === "on",
    "network.http.http3.enable":   false,
  };
}

/**
 * Parses raw text into a list of domain strings.
 * Strips whitespace, blank lines, and `#`-prefixed comment lines.
 *
 * @param {string} text
 * @returns {string[]}
 */
function parseDomainList(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}


/**
 * Reads and parses a domain list from disk.
 *
 * @param {string} filePath
 * @returns {Promise<string[]>}
 */
async function loadDomains(filePath) {
  const text = await fs.readFile(filePath, "utf8");
  return parseDomainList(text);
}

/**
 * Calls `fn` and silently logs any error it throws.
 * Used for best-effort cleanup (page/context close) that must not mask
 * the original error from the outer try/catch.
 *
 * @param {string} label  Shown in the error message for easy grep.
 * @param {() => Promise<void>} fn
 */
async function safeClose(label, fn) {
  try {
    await fn();
  } catch (err) {
    console.error(`[cleanup:${label}] ${String(err?.message ?? err)}`);
  }
}

/**
 * Navigates to `https://<domain>/` through the given proxy and returns a
 * structured result record.
 *
 * @typedef {Object} ProbeResult
 * @property {string}       proxy
 * @property {string}       proxyServer
 * @property {string}       domain
 * @property {string}       url
 * @property {boolean}      ok          — true if HTTP 2xx
 * @property {number|null}  status
 * @property {string|null}  error       — stringified error message, or null
 * @property {string}       startedAt   — ISO 8601
 * @property {string}       finishedAt  — ISO 8601
 * @property {string}       tlsVersion
 * @property {string}       postQuantum — "on" | "off" | "n/a"
 *
 * @param {import('playwright').Browser} browser
 * @param {{ name: string, server: string }} proxy
 * @param {string} domain
 * @returns {Promise<ProbeResult>}
 */
async function probe(browser, proxy, domain) {
  const url       = `https://${domain}/`;
  const startedAt = new Date().toISOString();

  let context = null;
  let page    = null;
  let ok      = false;
  let status  = null;
  let error   = null;

  try {
    context = await browser.newContext({
      proxy: { server: proxy.server },
      ignoreHTTPSErrors: true,
    });

    page = await context.newPage();

    const response = await page.goto(url, {
      waitUntil: "load",
      timeout: NAV_TIMEOUT,
    });

    status = response?.status() ?? null;
    ok     = !!response && response.ok();
  } catch (err) {
    error = String(err?.message ?? err);
  } finally {
    if (page)    await safeClose("page.close",    () => page.close());
    if (context) await safeClose("context.close", () => context.close());
  }

  return {
    proxy:       proxy.name,
    proxyServer: proxy.server,
    domain,
    url,
    ok,
    status,
    error,
    startedAt,
    finishedAt:  new Date().toISOString(),
    tlsVersion:  TLS_VERSION,
    postQuantum: POST_QUANTUM_EFFECTIVE,
  };
}

async function main() {
  const domains = await loadDomains(DOMAINS_FILE);
  if (domains.length === 0) throw new Error(`No domains found in ${DOMAINS_FILE}`);

  console.log(`Loaded ${domains.length} domains from ${DOMAINS_FILE}`);
  console.log(`TLS ${TLS_VERSION} | post-quantum: ${POST_QUANTUM_EFFECTIVE} | proxy: ${PROXY_NAME} (${PROXY_SERVER})`);

  const prefs = buildFirefoxPrefs();
  console.log("Firefox prefs:", JSON.stringify(prefs));

  const results = [];
  const proxy   = { name: PROXY_NAME, server: PROXY_SERVER };

  for (let i = 0; i < domains.length; i += BATCH_SIZE) {
    const batch       = domains.slice(i, i + BATCH_SIZE);
    const batchNumber = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(domains.length / BATCH_SIZE);
    console.log(`\n--- Batch ${batchNumber}/${totalBatches} (${batch.length} domains) ---`);

    const browser = await firefox.launch({ headless: true, firefoxUserPrefs: prefs });

    for (const domain of batch) {
      console.log(`  [${proxy.name}] ${domain}`);
      try {
        results.push(await probe(browser, proxy, domain));
      } catch (err) {
        console.error(`  [error] ${domain}: ${err.message}`);
      }
    }

    await browser.close().catch(() => {});
  }

  await fs.mkdir("results", { recursive: true });
  await fs.writeFile(OUT_JSON, JSON.stringify(results, null, 2));
  console.log(`\nWrote ${results.length} results → ${OUT_JSON}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
