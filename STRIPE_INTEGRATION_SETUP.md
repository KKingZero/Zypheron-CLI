# Stripe Buy Button Integration Setup

## ✅ Completed Implementation

### 1. **Stripe Buy Buttons Added**
- Integrated Stripe's buy button script into the billing page
- Added custom TypeScript declarations for `stripe-buy-button` elements
- Created styling for Stripe buttons to match COBRA AI theme

### 2. **UI Updates**
- **Billing Page**: Replaced custom subscribe buttons with Stripe buy buttons
- **Landing Page**: Added grey "Login" button in the navigation
- **Login Button**: Shows only when user is not authenticated

### 3. **Button Configuration**
Currently using the provided configuration:
- **Lite Plan**: Uses `buy_btn_1RmQQBABd1WNp9IUa8RSXQ9R`
- **Pro Plan**: Needs specific buy button ID (currently using Lite's ID)
- **Enterprise Plan**: Needs specific buy button ID (currently using Lite's ID)

## 🔧 Required Configuration

### 1. **Create Stripe Buy Buttons for Each Plan**

You provided these payment links:
- Lite: `https://buy.stripe.com/4gMdR8epq9RVdXFaBQdAk00`
- Pro: `https://buy.stripe.com/28EbJ02GId47bPx9xMdAk01`  
- Enterprise: `https://buy.stripe.com/bJebJ0chi0hlf1JdO2dAk02`

**Next Steps:**
1. Go to your Stripe Dashboard → Products → Buy Buttons
2. Create buy buttons for Pro and Enterprise plans
3. Get the `buy-button-id` for each plan
4. Update the code below

### 2. **Update Buy Button IDs**

Replace these in `frontend/src/pages/Billing.tsx`:

```tsx
// Pro Plan (line ~415)
<stripe-buy-button
  buy-button-id="PUT_PRO_BUY_BUTTON_ID_HERE"
  publishable-key="pk_live_51RCvg8ABd1WNp9IUoYjoeOcrfPhok203K7zGGLcjWTEAIQBp1EMUfjXlSiaZVDYZAeQuZpOO9kuzUUI16PMfVq3s00qKiXx7xk"
></stripe-buy-button>

// Enterprise Plan (line ~468)
<stripe-buy-button
  buy-button-id="PUT_ENTERPRISE_BUY_BUTTON_ID_HERE"
  publishable-key="pk_live_51RCvg8ABd1WNp9IUoYjoeOcrfPhok203K7zGGLcjWTEAIQBp1EMUfjXlSiaZVDYZAeQuZpOO9kuzUUI16PMfVq3s00qKiXx7xk"
></stripe-buy-button>
```

## 🎨 Styling Features

### 1. **Custom CSS**
- Created `frontend/src/styles/stripe.css` for consistent button styling
- Buttons match COBRA AI's red theme
- Full-width responsive design

### 2. **TypeScript Support**
- Added `frontend/src/types/stripe.d.ts` for TypeScript compatibility
- Eliminates linter errors for custom Stripe elements

## 🔄 User Flow

### 1. **Landing Page**
- Grey "Login" button in navigation
- "Get Started" buttons redirect to login → billing flow

### 2. **Billing Page**
- Shows current subscription status (if logged in)
- Displays all plans with Stripe buy buttons
- Login button appears if user not authenticated

### 3. **Payment Flow**
1. User clicks Stripe buy button
2. Redirected to Stripe Checkout
3. After payment, redirected back to your success URL
4. Stripe webhook updates subscription status

## 🔗 Integration Points

### 1. **Webhook Integration**
Your existing webhook at `/api/billing/webhook` will handle:
- Payment confirmation
- Subscription updates
- Customer creation

### 2. **Success/Cancel URLs**
Configure in Stripe Dashboard:
- **Success URL**: `https://yourdomain.com/billing?success=true`
- **Cancel URL**: `https://yourdomain.com/billing?canceled=true`

## 🧪 Testing

### 1. **Test Mode**
For development, use test publishable key:
```
pk_test_51RCvg8ABd1WNp9IU...
```

### 2. **Live Mode**
You're currently configured for live payments with:
```
pk_live_51RCvg8ABd1WNp9IUoYjoeOcrfPhok203K7zGGLcjWTEAIQBp1EMUfjXlSiaZVDYZAeQuZpOO9kuzUUI16PMfVq3s00qKiXx7xk
```

## 📋 Next Steps

1. **Create Pro and Enterprise buy buttons** in Stripe Dashboard
2. **Update buy-button-ids** in the billing page code
3. **Configure success/cancel URLs** in Stripe
4. **Test the complete flow** from landing page to payment
5. **Set up webhook endpoints** to handle payment events

## 🔒 Security Notes

- Publishable keys are safe to use in frontend code
- Keep secret keys on backend only
- All payment processing handled by Stripe (PCI compliant)
- No card data touches your servers

## 📞 Support

If you need the specific buy button IDs for Pro and Enterprise plans, please:
1. Check your Stripe Dashboard → Products → Buy Buttons
2. Or provide the buy button IDs from your Stripe account
3. Update the billing page code accordingly 