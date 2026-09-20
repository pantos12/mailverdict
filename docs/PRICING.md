# MailVerdict pricing and unit economics

The hosted service is priced at **$2.99 per mailbox per month**. This
document shows what a mailbox costs to serve, where the margin goes, and why
the annual plan matters more than it looks.

All figures are estimates as of September 2026. Re-check vendor pricing
before publishing them anywhere.

## 1. Variable cost per email

| component | assumption | cost per email |
| --- | --- | --- |
| Jev (TypeSafe System One) | ~2,800 input tokens (state + questions) at $0.042 / M; output free | $0.000118 |
| Explainer (OpenRouter, cheap model) | ~2,500 input at $0.15 / M + ~120 output at $0.60 / M = $0.00045 per call, invoked on 15% of emails | $0.000067 |
| Vercel function time | ~1 s at ~$0.00002 / GB-s, 1 GB | $0.00002 |
| **Total** | | **~$0.0002** |

Round it to **$0.0002 per email**. A mailbox that forwards 200 emails a month
costs **$0.04** to serve; the fair-use cap of 1,000 analyses a month costs
**$0.20**. Even a pathological mailbox at the cap leaves 93% of the sticker
price before fixed costs and fees.

If the review rate creeps to 20%, the explainer line rises to $0.00009 and the
total stays near $0.0002. If a tenant enables `explainPhishing`, add one
explainer call per phishing email; that is still under $0.0007 per email.

## 2. Fixed costs

| item | monthly |
| --- | --- |
| Vercel Pro (required for commercial use; Hobby is non-commercial) | $20 |
| Domain | ~$1 |
| Stripe (no monthly fee on standard pricing) | $0 |
| Status page / uptime monitor (optional, free tier) | $0 |
| **Total** | **~$21** |

Vercel Pro includes enough function invocations and compute for tens of
thousands of analyses before overage. At a few hundred mailboxes, usage-based
Vercel charges are still single-digit dollars.

## 3. Payment fees: the $2.99 problem

Stripe's standard card rate is **2.9% + $0.30** per transaction.

| plan | price | Stripe fee | fee as % of price | net |
| --- | --- | --- | --- | --- |
| Monthly | $2.99 | $0.387 | **12.9%** | $2.60 |
| Annual | $29.00 | $1.141 | 3.9% | $27.86 |
| Team monthly (10 mailboxes) | $19.00 | $0.851 | 4.5% | $18.15 |

On a $2.99 charge the fixed $0.30 alone is 10% of revenue. Monthly billing at
this price point hands Stripe more than the entire cost of serving the
mailbox. This is the honest reason to push annual billing and bundles, not a
marketing preference:

- **Annual $29** (two months free) cuts the fee share from 12.9% to 3.9% and
  removes eleven card-decline / dunning cycles a year.
- **Team $19 for 10 mailboxes** is $1.90 per mailbox with a 4.5% fee share.
- If you must offer monthly, consider a $2.99 minimum with a 3-month
  minimum term, or bill quarterly ($8.97: fee $0.56, 6.2%).

Stripe's 0.5% recurring-billing fee (Billing) applies if you use Stripe
Billing subscriptions rather than Payment Links; on $29 that is $0.15, still
worth it for automatic renewals and dunning.

## 4. Margin and break-even

Per Personal mailbox, monthly plan, 200 emails / month:

```text
price                       $2.99
Stripe fee                 -$0.39
variable cost (200 emails) -$0.04
contribution              = $2.56   (86%)
```

Per Personal mailbox, annual plan (amortised monthly):

```text
price (29 / 12)             $2.42
Stripe fee (1.14 / 12)     -$0.10
variable cost              -$0.04
contribution              = $2.28   (94%)
```

Break-even on ~$21 fixed cost: **9 monthly mailboxes** or **10 annual
mailboxes**. One Team plan ($18.15 net, ~$0.40 variable) covers almost the
whole fixed base by itself.

At 100 mailboxes (a mix of plans averaging $2.40 contribution): ~$240 / month
contribution, ~$219 after fixed costs. At 1,000: ~$2,400 / month. The cost
side scales at $0.0002 per email, so margin stays above 85% until support
time becomes the real cost.

## 5. Suggested tiers

| tier | price | includes | who |
| --- | --- | --- | --- |
| **Self-host** | free (MIT) | the repo; bring your own TypeSafe, OpenRouter and Vercel accounts | developers, security teams with a platform |
| **Personal** | $2.99 / month or $29 / year | 1 mailbox, 1 API key, MCP + REST, fair use 1,000 analyses / month | individuals, freelancers, one shared `phish@` mailbox |
| **Team** | $19 / month or $190 / year | 10 mailboxes, shared key, Teams posting recipe, email support | SMBs with a small IT function |
| **MSP** | contact | per-tenant keys, usage export, custom thresholds per tenant, priority support, invoice billing | managed service providers protecting many tenants |

Fair-use cap: 1,000 analyses / mailbox / month, soft-enforced (warn, then
throttle). At $0.0002 per email even a mailbox at 5x the cap is profitable,
so the cap exists to stop automated abuse, not to upsell.

## 6. Stripe Payment Link setup (no code)

Payment Links give you a hosted checkout page with no integration work. Good
enough until you need to provision API keys automatically.

1. **Stripe Dashboard > Product catalog > + Add product.**
   - Name: `MailVerdict Personal`. Description: `Calibrated phishing verdicts for one mailbox`.
   - Pricing: **Recurring**, $2.99 USD, **Monthly**. Save.
   - On the product page, **+ Add another price**: Recurring, $29.00, **Yearly**.
   - Repeat for `MailVerdict Team`: $19 monthly and $190 yearly.
2. **Payment Links > + New.**
   - Select the product and price. Enable **Let customers adjust quantity**
     for Team if you want 20- or 30-mailbox orders without a new SKU.
   - **Options**: collect customer email (required), collect billing address
     (needed for tax), allow promotion codes (for beta testers).
   - **After payment**: "Don't show confirmation page" and redirect to
     `https://<your-site>/welcome?session_id={CHECKOUT_SESSION_ID}` so the
     welcome page can show onboarding steps.
   - Create the link. Make one link per price (monthly and yearly), or one
     link with the yearly price and show the monthly link as a secondary
     option; the annual-first layout nudges toward the lower-fee plan.
3. **Settings > Billing > Subscriptions and emails**: enable customer emails
   for successful payments, upcoming renewals and failed payments. Turn on
   **Smart Retries** and set a cancellation after the final failed retry so
   unpaid mailboxes do not keep an active key.
4. **Settings > Customer portal**: enable it so customers can cancel, switch
   monthly to yearly, and update cards without emailing you. Put the portal
   link in the welcome email.
5. **Settings > Tax**: enable Stripe Tax if you sell outside your home
   jurisdiction. It adds 0.5% but avoids handling VAT/GST registration
   thresholds by hand.
6. **Provisioning (manual to start)**: Stripe emails you on each new
   subscription. Generate a key (`openssl rand -hex 32`), add it to the
   allow-list your deployment reads (a Vercel env var or a small KV store),
   and send the customer the key plus the link to `docs/COPILOT_STUDIO.md`.
   Automate this with a Stripe webhook once volume justifies it; that is on
   the roadmap in the README.
7. **Test**: use Stripe's test mode toggle, create a link, pay with card
   `4242 4242 4242 4242`, confirm the subscription appears and the emails
   fire, then switch to live mode and recreate the links.

## 7. What would change these numbers

- **Jev price changes.** At 10x the current token price the variable cost
  is still ~$0.0014 per email; the model is robust to it.
- **Explainer on every email.** Multiplies the LLM line by ~7; total rises
  to ~$0.0006. Still fine, but there is no product reason to do it.
- **Attachment detonation** (roadmap). Sandboxing is the first feature that
  would cost more than a cent per email; it should be a Team/MSP add-on.
- **Support load.** Above a few hundred mailboxes, an hour of support per
  week is worth more than the infrastructure. Price MSP tiers on that, not
  on tokens.
