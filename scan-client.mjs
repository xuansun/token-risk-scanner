/**
 * x402 client: calls the token risk scanner API with automatic payment handling.
 * Requires PRIVATE_KEY env var pointing to a Base Sepolia wallet with USDC.
 */

import { privateKeyToAccount } from "viem/accounts";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";

const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) {
  console.error("ERROR: Set PRIVATE_KEY environment variable (hex, 0x-prefixed)");
  process.exit(1);
}

const account = privateKeyToAccount(PRIVATE_KEY);
console.log(`Wallet: ${account.address}`);

// Build x402 client — registerExactEvmScheme wires in eip155:* wildcard + V1 networks
const baseClient = new x402Client();
registerExactEvmScheme(baseClient, { signer: account });

const httpClient = new x402HTTPClient(baseClient);

const url =
  "https://token-risk-scanner-production.up.railway.app/scan" +
  "?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chain=base";

console.log(`\nScanning: ${url}\n`);

// ── Step 1: probe — expect a 402 ──────────────────────────────────────────────
const probe = await fetch(url);

if (probe.status !== 402) {
  // Somehow got through without payment
  const body = await probe.json();
  console.log(JSON.stringify(body, null, 2));
  process.exit(0);
}

// ── Step 2: decode payment requirements from header ───────────────────────────
let paymentRequired;
try {
  paymentRequired = httpClient.getPaymentRequiredResponse(
    (name) => probe.headers.get(name)
  );
} catch (e) {
  console.error("Could not decode PAYMENT-REQUIRED header:", e.message);
  const body = await probe.json().catch(() => probe.text());
  console.error("Response body:", body);
  process.exit(1);
}

const req = paymentRequired.accepts?.[0];
console.log("Payment required:");
console.log(`  Scheme:  ${req?.scheme}`);
console.log(`  Network: ${req?.network}`);
console.log(`  Amount:  ${req?.amount} (${Number(req?.amount) / 1e6} USDC)`);
console.log(`  Asset:   ${req?.asset}`);
console.log(`  PayTo:   ${req?.payTo}`);
console.log();

// ── Step 3: sign the payment authorization ────────────────────────────────────
let paymentPayload;
try {
  paymentPayload = await httpClient.createPaymentPayload(paymentRequired);
} catch (e) {
  console.error("Failed to create payment payload:", e.message);
  process.exit(1);
}

const paymentHeaders = httpClient.encodePaymentSignatureHeader(paymentPayload);
console.log("Payment signed. Submitting with PAYMENT-SIGNATURE header...\n");

// ── Step 4: retry with the signed payment ────────────────────────────────────
const paid = await fetch(url, { headers: paymentHeaders });

if (!paid.ok) {
  const errorBody = await paid.text();
  console.error(`Payment rejected (${paid.status}):`, errorBody);
  process.exit(1);
}

const result = await paid.json();

// ── Step 5: print the risk report ────────────────────────────────────────────
console.log("=".repeat(60));
console.log(`Token:     ${result.token_name} (${result.token_symbol})`);
console.log(`Contract:  ${result.contract}`);
console.log(`Chain ID:  ${result.chain_id}`);
console.log(`Verdict:   ${result.verdict}  (score: ${result.risk_score}/100)`);
console.log(`Taxes:     buy ${result.tax?.buy_tax_percent}%  /  sell ${result.tax?.sell_tax_percent}%`);
console.log();

if (result.risks?.length) {
  console.log("Risks:");
  for (const r of result.risks) {
    console.log(`  [${r.level}] ${r.flag} — ${r.detail}`);
  }
  console.log();
}

if (result.positives?.length) {
  console.log("Positives:");
  for (const p of result.positives) {
    console.log(`  ✓ ${p}`);
  }
  console.log();
}

if (result.dex?.length) {
  console.log("DEX liquidity:");
  for (const d of result.dex) {
    console.log(`  ${d.name}: $${Number(d.liquidity).toLocaleString()} (pair: ${d.pair})`);
  }
}

console.log("=".repeat(60));
console.log(`Scanned at: ${result.scanned_at}  |  Source: ${result.data_source}`);
