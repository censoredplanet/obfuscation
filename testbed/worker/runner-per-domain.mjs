/**
 * runner-per-domain.mjs — single-domain TLS probe
 *
 * Results are appended as JSON Lines so parallel or sequential invocations
 * targeting the same output file do not corrupt each other.
 *
 * Usage:
 *   node runner-per-domain.mjs <proxy-name> <proxy-server> [tls-version] [post-quantum] --domain <domain>
 *
 * Arguments:
 *   proxy-name    Short label written into the result record (e.g. "gost")
 *   proxy-server  SOCKS5 URL (e.g. "socks5://127.0.0.1:1080")
 *   tls-version   "1.2" or "1.3" (default: "1.3")
 *   post-quantum  "on" or "off" — enables ML-KEM/Kyber in TLS 1.3 (default: "on")
 *   --domain      Domain to probe (required)
 *
 * Output:
 *   results/results.<proxy-name>.jsonl
 */

import { firefox } from "playwright";
import fs from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);

const PROXY_NAME   = args[0];
const PROXY_SERVER = args[1];
const TLS_VERSION  = args[2] ?? "1.3";  // "1.2" or "1.3"
const POST_QUANTUM = args[3] ?? "on";   // "on"  or "off"

const DOMAIN_FLAG  = args.indexOf("--domain");
const TARGET_DOMAIN = DOMAIN_FLAG !== -1 ? args[DOMAIN_FLAG + 1] : null;

if (!PROXY_NAME || !PROXY_SERVER || !TARGET_DOMAIN) {
  console.error("Usage: node runner-per-domain.mjs <proxy-name> <proxy-server> [tls-version] [post-quantum] --domain <domain>");
  console.error('Example: node runner-per-domain.mjs gost "socks5://127.0.0.1:1080" 1.3 on --domain example.com');
  process.exit(1);
}

const POST_QUANTUM_EFFECTIVE = TLS_VERSION === "1.3" ? POST_QUANTUM : "n/a";

const OUT_FILE    = `results/results.${PROXY_NAME}.jsonl`;
const NAV_TIMEOUT = 60_000; // ms — longer than the batch script to allow for transient network issues

/**
 * Returns the firefox about:config overrides for the requested TLS mode.
 * HTTP/3 is disabled so all traffic goes through the SOCKS proxy reliably.
 *
 * @returns {Record<string, boolean | number>}
 */
function buildFirefoxPrefs() {
  return {
    "security.tls.version.min":  1,
    "security.tls.version.max":  TLS_VERSION === "1.2" ? 3 : 4,
    "security.tls.enable_kyber": POST_QUANTUM === "on",
    "network.http.http3.enable": false,
  };
}

/**
 * Navigates to `https://<domain>/` and returns a structured result record.
 *
 * @typedef {Object} ProbeResult
 * @property {string}       proxy
 * @property {string}       domain
 * @property {boolean}      ok          — true if HTTP 2xx
 * @property {number|null}  status
 * @property {string|null}  error       — stringified error message, or null
 * @property {string}       startedAt   — ISO 8601
 * @property {string}       finishedAt  — ISO 8601
 * @property {string}       tlsVersion
 * @property {string}       postQuantum — "on" | "off" | "n/a"
 *
 * @param {import('playwright').Browser} browser
 * @param {string} domain
 * @returns {Promise<ProbeResult>}
 */
async function probe(browser, domain) {
  const url       = `https://${domain}/`;
  const startedAt = new Date().toISOString();

  let context = null;
  let page    = null;
  let ok      = false;
  let status  = null;
  let error   = null;

  try {
    context = await browser.newContext({
      proxy: { server: PROXY_SERVER },
      ignoreHTTPSErrors: true,
    });

    page = await context.newPage();

    const response = await page.goto(url, { waitUntil: "load", timeout: NAV_TIMEOUT });

    status = response?.status() ?? null;
    ok     = !!response && response.ok();
  } catch (err) {
    error = String(err?.message ?? err);
  } finally {
    if (page)    await page.close().catch(() => {});
    if (context) await context.close().catch(() => {});
  }

  return {
    proxy:       PROXY_NAME,
    domain,
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
  await fs.mkdir(path.dirname(OUT_FILE), { recursive: true });

  const browser = await firefox.launch({
    headless: true,
    firefoxUserPrefs: buildFirefoxPrefs(),
  });

  try {
    const result = await probe(browser, TARGET_DOMAIN);
    await fs.appendFile(OUT_FILE, JSON.stringify(result) + "\n");

    if (result.ok) console.log(`[success] ${TARGET_DOMAIN} (HTTP ${result.status})`);
    else           console.log(`[fail]    ${TARGET_DOMAIN} — ${result.error ?? `HTTP ${result.status}`}`);
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
