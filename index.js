// ============================================
// Token Risk Scanner — x402-powered API
// Checks smart contracts for honeypots, rug
// pulls, and scam signals. Pay per scan.
// ============================================

import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import dotenv from "dotenv";

dotenv.config({ override: false });

const app = express();
app.use(express.json());

// ── Config ──────────────────────────────────
const payTo = process.env.WALLET_ADDRESS;
const network = process.env.NETWORK || "eip155:84532";
const PORT = process.env.PORT || 4021;

/*if (!payTo) {
  console.error("ERROR: Set WALLET_ADDRESS in your .env file");
  process.exit(1);
}*/

console.log("WALLET_ADDRESS from env:", process.env.WALLET_ADDRESS);

if (!payTo) {
  console.error("ERROR: Set WALLET_ADDRESS in environment variables");
  process.exit(1);
}

// ── x402 Setup ──────────────────────────────
const facilitatorClient = new HTTPFacilitatorClient({
  url: process.env.FACILITATOR_URL || "https://x402.org/facilitator",
});
const server = new x402ResourceServer(facilitatorClient).register(
  network,
  new ExactEvmScheme()
);

// ── Chain ID mapping for GoPlus ─────────────
// GoPlus uses numeric chain IDs
const CHAIN_MAP = {
  ethereum: "1",
  eth: "1",
  bsc: "56",
  "binance smart chain": "56",
  base: "8453",
  polygon: "137",
  arbitrum: "42161",
  avalanche: "43114",
  optimism: "10",
  fantom: "250",
  linea: "59144",
  scroll: "534352",
  zksync: "324",
  // Default to Base since we're in the x402 ecosystem
  default: "8453",
};

function resolveChainId(input) {
  if (!input) return CHAIN_MAP.default;
  const cleaned = input.toLowerCase().trim();
  // If it's already a number, return it
  if (/^\d+$/.test(cleaned)) return cleaned;
  return CHAIN_MAP[cleaned] || CHAIN_MAP.default;
}

// ── GoPlus API wrapper ──────────────────────
// GoPlus provides FREE token security data
// Docs: https://docs.gopluslabs.io
async function fetchTokenSecurity(chainId, contractAddress) {
  const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${contractAddress}`;

  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
  });

  if (!response.ok) {
    throw new Error(`GoPlus API returned ${response.status}`);
  }

  const data = await response.json();

  if (data.code !== 1) {
    throw new Error(data.message || "GoPlus API error");
  }

  // GoPlus returns data keyed by lowercase address
  const key = contractAddress.toLowerCase();
  const tokenData = data.result?.[key];

  if (!tokenData) {
    return null; // Token not found
  }

  return tokenData;
}

// ── Risk scoring engine ─────────────────────
// Turns raw GoPlus data into a simple risk report
function analyzeRisk(raw) {
  const risks = [];
  let riskScore = 0;

  // --- Critical risks (instant red flags) ---
  if (raw.is_honeypot === "1") {
    risks.push({ level: "CRITICAL", flag: "honeypot", detail: "Token cannot be sold — this is a honeypot scam" });
    riskScore += 40;
  }
  if (raw.cannot_sell_all === "1") {
    risks.push({ level: "CRITICAL", flag: "cannot_sell_all", detail: "Holders cannot sell all their tokens" });
    riskScore += 30;
  }

  // --- High risks ---
  if (raw.is_mintable === "1") {
    risks.push({ level: "HIGH", flag: "mintable", detail: "Contract owner can mint unlimited new tokens, diluting holders" });
    riskScore += 20;
  }
  if (raw.can_take_back_ownership === "1") {
    risks.push({ level: "HIGH", flag: "can_reclaim_ownership", detail: "Ownership can be reclaimed even after renouncement" });
    riskScore += 20;
  }
  if (raw.owner_change_balance === "1") {
    risks.push({ level: "HIGH", flag: "owner_can_change_balance", detail: "Contract owner can modify token balances" });
    riskScore += 25;
  }
  if (raw.hidden_owner === "1") {
    risks.push({ level: "HIGH", flag: "hidden_owner", detail: "Contract has a hidden owner who retains control" });
    riskScore += 20;
  }
  if (raw.selfdestruct === "1") {
    risks.push({ level: "HIGH", flag: "self_destruct", detail: "Contract can self-destruct, destroying all tokens" });
    riskScore += 20;
  }
  if (raw.external_call === "1") {
    risks.push({ level: "HIGH", flag: "external_call", detail: "Contract makes external calls — potential for hidden logic" });
    riskScore += 15;
  }

  // --- Medium risks ---
  if (raw.is_open_source === "0") {
    risks.push({ level: "MEDIUM", flag: "closed_source", detail: "Contract source code is not verified — cannot audit" });
    riskScore += 15;
  }
  if (raw.is_proxy === "1") {
    risks.push({ level: "MEDIUM", flag: "proxy_contract", detail: "Contract uses a proxy — logic can be changed" });
    riskScore += 10;
  }
  if (raw.is_blacklisted === "1") {
    risks.push({ level: "MEDIUM", flag: "blacklist_function", detail: "Contract can blacklist addresses from trading" });
    riskScore += 10;
  }
  if (raw.is_whitelisted === "1") {
    risks.push({ level: "MEDIUM", flag: "whitelist_function", detail: "Contract uses a whitelist — may restrict trading" });
    riskScore += 5;
  }
  if (raw.transfer_pausable === "1") {
    risks.push({ level: "MEDIUM", flag: "pausable", detail: "Transfers can be paused by the contract owner" });
    riskScore += 10;
  }
  if (raw.anti_whale_modifiable === "1") {
    risks.push({ level: "MEDIUM", flag: "anti_whale_modifiable", detail: "Anti-whale limits can be changed by owner" });
    riskScore += 5;
  }
  if (raw.trading_cooldown === "1") {
    risks.push({ level: "MEDIUM", flag: "trading_cooldown", detail: "There is a mandatory cooldown between trades" });
    riskScore += 5;
  }
  if (raw.personal_slippage_modifiable === "1") {
    risks.push({ level: "MEDIUM", flag: "slippage_modifiable", detail: "Tax/slippage can be changed per address" });
    riskScore += 10;
  }

  // --- Tax analysis ---
  const buyTax = parseFloat(raw.buy_tax || "0");
  const sellTax = parseFloat(raw.sell_tax || "0");
  if (sellTax > 0.1) {
    risks.push({ level: "HIGH", flag: "high_sell_tax", detail: `Sell tax is ${(sellTax * 100).toFixed(1)}% — significantly eats into profits` });
    riskScore += 15;
  } else if (sellTax > 0.05) {
    risks.push({ level: "MEDIUM", flag: "moderate_sell_tax", detail: `Sell tax is ${(sellTax * 100).toFixed(1)}%` });
    riskScore += 5;
  }
  if (buyTax > 0.1) {
    risks.push({ level: "HIGH", flag: "high_buy_tax", detail: `Buy tax is ${(buyTax * 100).toFixed(1)}%` });
    riskScore += 10;
  }

  // --- Positive signals ---
  const positives = [];
  if (raw.is_open_source === "1") positives.push("Contract is verified and open-source");
  if (raw.owner_address === "0x0000000000000000000000000000000000000000") positives.push("Ownership renounced");
  if (raw.is_honeypot === "0") positives.push("Not a honeypot — selling is possible");
  if (raw.is_mintable === "0") positives.push("No mint function — supply is fixed");
  if (sellTax === 0 && buyTax === 0) positives.push("Zero buy/sell tax");

  // Cap at 100
  riskScore = Math.min(riskScore, 100);

  // Determine verdict
  let verdict;
  if (riskScore >= 70) verdict = "DANGEROUS";
  else if (riskScore >= 40) verdict = "RISKY";
  else if (riskScore >= 15) verdict = "CAUTION";
  else verdict = "LOW_RISK";

  return {
    risk_score: riskScore,
    verdict,
    risks,
    positives,
    tax: {
      buy_tax_percent: Math.round(buyTax * 100 * 10) / 10,
      sell_tax_percent: Math.round(sellTax * 100 * 10) / 10,
    },
  };
}

// ── Protected routes (require x402 payment) ─
app.use(
  paymentMiddleware(
    {
      "GET /scan": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.003",
            network,
            payTo,
          },
        ],
        description:
          "Scan a token contract for security risks: honeypots, rug pulls, hidden owners, tax traps, and more. Returns a risk score (0-100), verdict, and detailed findings.",
        mimeType: "application/json",
      },
    },
    server
  )
);

// ── GET /scan — the main endpoint ───────────
app.get("/scan", async (req, res) => {
  const { address, chain } = req.query;

  if (!address) {
    return res.status(400).json({
      error: "Missing 'address' query parameter",
      usage: "GET /scan?address=0x...&chain=base",
      example: "/scan?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chain=base",
    });
  }

  // Validate address format
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({
      error: "Invalid contract address format",
      detail: "Must be a valid EVM address starting with 0x followed by 40 hex characters",
    });
  }

  const chainId = resolveChainId(chain);

  try {
    const raw = await fetchTokenSecurity(chainId, address);

    if (!raw) {
      return res.status(404).json({
        error: "Token not found",
        detail: `No security data found for ${address} on chain ${chainId}. The token may be too new, on an unsupported chain, or not yet indexed.`,
      });
    }

    const analysis = analyzeRisk(raw);

    // Build the response
    const result = {
      contract: address,
      chain_id: chainId,
      token_name: raw.token_name || null,
      token_symbol: raw.token_symbol || null,
      total_supply: raw.total_supply || null,
      holder_count: raw.holder_count ? parseInt(raw.holder_count) : null,
      creator_address: raw.creator_address || null,
      owner_address: raw.owner_address || null,
      // Core analysis
      risk_score: analysis.risk_score,
      verdict: analysis.verdict,
      tax: analysis.tax,
      risks: analysis.risks,
      positives: analysis.positives,
      // Liquidity info (useful for trading agents)
      dex: raw.dex
        ? raw.dex.map((d) => ({
            name: d.name,
            liquidity: d.liquidity,
            pair: d.pair,
          }))
        : [],
      // Metadata
      scanned_at: new Date().toISOString(),
      data_source: "GoPlus Security",
    };

    res.json(result);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(502).json({
      error: "Failed to fetch security data",
      detail: err.message,
    });
  }
});

// ── Free routes (no payment needed) ─────────

// Health check
app.get("/", (req, res) => {
  res.json({
    service: "Token Risk Scanner",
    version: "1.0.0",
    description:
      "Pay-per-scan token security analysis for AI agents. Checks for honeypots, rug pulls, hidden owners, and tax traps.",
    pricing: "$0.003 USDC per scan",
    network: network,
    endpoints: {
      "GET /": "This health check (free)",
      "GET /chains": "List supported chains (free)",
      "GET /scan?address=0x...&chain=base": "Scan a token contract (paid, $0.003)",
    },
    example:
      "GET /scan?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chain=base",
  });
});

// List supported chains (free)
app.get("/chains", (req, res) => {
  res.json({
    supported_chains: Object.entries(CHAIN_MAP)
      .filter(([key]) => key !== "default")
      .map(([name, id]) => ({ name, chain_id: id })),
    default_chain: "base (8453)",
    note: "You can pass either the chain name or numeric chain ID in the 'chain' query parameter.",
  });
});

// ── Start ───────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("  ╔══════════════════════════════════════════╗");
  console.log("  ║       Token Risk Scanner — x402          ║");
  console.log("  ╠══════════════════════════════════════════╣");
  console.log(`  ║  Server:    http://localhost:${PORT}         ║`);
  console.log(`  ║  Network:   ${network.padEnd(28)}║`);
  console.log(`  ║  Wallet:    ${payTo.slice(0, 10)}...${payTo.slice(-6)}           ║`);
  console.log("  ║                                          ║");
  console.log("  ║  Endpoints:                              ║");
  console.log("  ║    GET /        Health check (free)       ║");
  console.log("  ║    GET /chains  Supported chains (free)   ║");
  console.log("  ║    GET /scan    Token scan ($0.003)       ║");
  console.log("  ╚══════════════════════════════════════════╝");
  console.log("");
});
