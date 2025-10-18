# Billing Integration TODO

## Overview
This file tracks the tasks needed to integrate billing for paid OSINT services in COBRA AI.

## Paid Services to Enable
When billing is integrated, the following paid OSINT services should be enabled based on user subscription:

1. **Shodan API** - Port & service scanning
   - Free tier: 100 results/month
   - Paid tiers: Starting at $59/month
   - API Key required: `SHODAN_API_KEY`

2. **Censys API** - Certificate transparency & host data
   - Free tier: 250 queries/month
   - Paid tiers: Starting at $99/month
   - API Key required: `CENSYS_API_ID` and `CENSYS_API_SECRET`

3. **VirusTotal API** - Malware scanning & reputation
   - Free tier: 500 requests/day, 4 requests/minute
   - Paid tiers: Enterprise pricing
   - API Key required: `VIRUSTOTAL_API_KEY`

4. **Have I Been Pwned API** - Data breach information
   - Free tier: Limited
   - Paid tier: $3.50/month
   - API Key required: `HIBP_API_KEY`

## Implementation Tasks

### Frontend (PentestPanel.tsx)
- [ ] Remove `disabled={true}` from paid service checkboxes
- [ ] Check user subscription status before enabling paid options
- [ ] Show subscription upgrade prompt when clicking disabled services
- [ ] Update the TODO comment in the component

### Backend Integration
- [ ] Create billing/subscription management endpoints
- [ ] Implement API key management system
- [ ] Add rate limiting based on subscription tier
- [ ] Store encrypted API keys per user/organization

### Database Schema
- [ ] Add subscription table
- [ ] Add api_keys table for storing encrypted keys
- [ ] Add usage_tracking table for monitoring API usage

### Environment Variables
Add to `.env`:
```
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
VIRUSTOTAL_API_KEY=
HIBP_API_KEY=
```

### User Experience
- [ ] Add billing/subscription page
- [ ] Show current API usage and limits
- [ ] Add notifications for approaching limits
- [ ] Graceful fallback when limits are reached

## Code Locations to Update
1. `frontend/src/components/PentestPanel.tsx` - Remove disabled state
2. `backend/src/routes/pentest.ts` - Add actual API calls
3. `backend/src/services/ai.ts` - Integrate real OSINT data
4. Create new `backend/src/services/billing.ts` for subscription management
5. Create new `backend/src/services/osint.ts` for API integrations

## Testing Checklist
- [ ] Test with free tier limits
- [ ] Test limit exceeded scenarios
- [ ] Test subscription upgrade flow
- [ ] Test API key rotation
- [ ] Test error handling for API failures 