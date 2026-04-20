# Token Risk Scanner — x402

A pay-per-scan token security API for AI agents. Checks smart contracts for honeypots, rug pulls, hidden owners, tax traps, and more.

**$0.003 USDC per scan** — no API keys, no accounts, no subscriptions.

## What it does

An AI agent sends a token contract address → you return a risk report:
- **Risk score** (0–100) with a verdict: `LOW_RISK`, `CAUTION`, `RISKY`, or `DANGEROUS`
- **Specific risk flags**: honeypot, mintable supply, hidden owner, high taxes, proxy contracts, etc.
- **Positive signals**: verified source, renounced ownership, zero taxes
- **Token metadata**: name, symbol, holder count, liquidity info

## Quick start

### 1. Clone & install

```bash
git clone <your-repo-url>
cd token-risk-scanner
npm install
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` and set your Base wallet address:
```
WALLET_ADDRESS=0xYourBaseWalletAddressHere
```

### 3. Run

```bash
npm start
```

### 4. Test

Visit these URLs in your browser:

- `http://localhost:4021/` — health check (free)
- `http://localhost:4021/chains` — list supported chains (free)
- `http://localhost:4021/scan?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chain=base` — scan USDC on Base (returns 402 — payment required!)

Getting the 402 response means it's working! That's the x402 protocol asking for payment before returning data.

## Endpoints

| Endpoint | Cost | Description |
|----------|------|-------------|
| `GET /` | Free | Health check + API docs |
| `GET /chains` | Free | List all supported chains |
| `GET /scan?address=0x...&chain=base` | $0.003 | Full token security scan |

### Scan parameters

| Param | Required | Description |
|-------|----------|-------------|
| `address` | Yes | Token contract address (0x...) |
| `chain` | No | Chain name or ID (default: `base`) |

Supported chains: `ethereum`, `bsc`, `base`, `polygon`, `arbitrum`, `avalanche`, `optimism`, `fantom`, `linea`, `scroll`, `zksync`

## Example response

```json
{
  "contract": "0x...",
  "chain_id": "8453",
  "token_name": "Example Token",
  "token_symbol": "EXT",
  "holder_count": 1234,
  "risk_score": 65,
  "verdict": "RISKY",
  "tax": { "buy_tax_percent": 5, "sell_tax_percent": 12 },
  "risks": [
    { "level": "HIGH", "flag": "high_sell_tax", "detail": "Sell tax is 12.0%..." },
    { "level": "HIGH", "flag": "mintable", "detail": "Contract owner can mint..." }
  ],
  "positives": [
    "Contract is verified and open-source",
    "Not a honeypot — selling is possible"
  ],
  "dex": [{ "name": "Uniswap V3", "liquidity": "125000.00", "pair": "0x..." }],
  "scanned_at": "2026-04-19T12:00:00.000Z",
  "data_source": "GoPlus Security"
}
```

## Deploy to Railway

1. Push this project to a GitHub repo
2. Go to [railway.app](https://railway.app) → "New Project" → "Deploy from GitHub"
3. Select your repo
4. Add environment variables in the Railway dashboard:
   - `WALLET_ADDRESS` = your Base wallet address
   - `FACILITATOR_URL` = `https://x402.org/facilitator`
   - `PORT` = `4021`
   - `NETWORK` = `eip155:84532` (testnet) or `eip155:8453` (mainnet)
5. Deploy!

## Going to mainnet

When you're ready to accept real USDC:

1. Change `NETWORK` to `eip155:8453` in your `.env` (or Railway vars)
2. Make sure your wallet has some ETH on Base for gas (very small amount needed)
3. Redeploy

## How it makes money

- Each scan costs the caller $0.003 in USDC
- GoPlus API is free — you pay nothing for the data
- Your margin is ~100% (your only costs are Railway hosting, ~$5/month)
- At 10,000 scans/month = $30/month revenue
- At 100,000 scans/month = $300/month revenue

## Tech stack

- **Express.js** — web server
- **@x402/express** — payment middleware
- **GoPlus Security API** — free token security data (no API key needed)
- **Base Sepolia / Base** — payment network

## License

MIT
