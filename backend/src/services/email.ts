import { supabase } from '../server'

// Email service interface for different providers
interface EmailProvider {
  sendEmail(to: string, subject: string, html: string, text?: string): Promise<boolean>
}

// Mock email provider for development
class MockEmailProvider implements EmailProvider {
  async sendEmail(to: string, subject: string, html: string, text?: string): Promise<boolean> {
    console.log(`📧 Mock Email Sent:`)
    console.log(`To: ${to}`)
    console.log(`Subject: ${subject}`)
    console.log(`HTML: ${html.substring(0, 100)}...`)
    return true
  }
}

// SendGrid email provider (implement when ready)
class SendGridEmailProvider implements EmailProvider {
  private apiKey: string

  constructor(apiKey: string) {
    this.apiKey = apiKey
  }

  async sendEmail(to: string, subject: string, html: string, text?: string): Promise<boolean> {
    try {
      // TODO: Implement SendGrid integration
      // const sgMail = require('@sendgrid/mail')
      // sgMail.setApiKey(this.apiKey)
      // 
      // const msg = {
      //   to,
      //   from: 'noreply@cobraai.app',
      //   subject,
      //   text,
      //   html,
      // }
      // 
      // await sgMail.send(msg)
      console.log(`📧 SendGrid Email would be sent to: ${to}`)
      return true
    } catch (error) {
      console.error('SendGrid email error:', error)
      return false
    }
  }
}

// Email service class
export class EmailService {
  private provider: EmailProvider

  constructor() {
    const sendGridApiKey = process.env.SENDGRID_API_KEY
    
    if (sendGridApiKey) {
      this.provider = new SendGridEmailProvider(sendGridApiKey)
    } else {
      console.warn('No email provider configured, using mock provider')
      this.provider = new MockEmailProvider()
    }
  }

  // Payment confirmation email
  async sendPaymentConfirmation(
    userId: string, 
    paymentIntent: any
  ): Promise<boolean> {
    try {
      const user = await this.getUserDetails(userId)
      if (!user?.email) return false

      const amount = (paymentIntent.amount / 100).toFixed(2)
      const currency = paymentIntent.currency.toUpperCase()
      const planName = paymentIntent.metadata?.plan_name || 'Subscription'

      const subject = `Payment Confirmation - ${planName} Plan`
      const html = this.generatePaymentConfirmationHTML(user, amount, currency, planName)
      const text = this.generatePaymentConfirmationText(user, amount, currency, planName)

      return await this.provider.sendEmail(user.email, subject, html, text)
    } catch (error) {
      console.error('Error sending payment confirmation email:', error)
      return false
    }
  }

  // Payment failure email
  async sendPaymentFailure(
    userId: string,
    paymentIntent: any
  ): Promise<boolean> {
    try {
      const user = await this.getUserDetails(userId)
      if (!user?.email) return false

      const amount = (paymentIntent.amount / 100).toFixed(2)
      const currency = paymentIntent.currency.toUpperCase()
      const error = paymentIntent.last_payment_error?.message || 'Payment processing failed'

      const subject = 'Payment Failed - Action Required'
      const html = this.generatePaymentFailureHTML(user, amount, currency, error)
      const text = this.generatePaymentFailureText(user, amount, currency, error)

      return await this.provider.sendEmail(user.email, subject, html, text)
    } catch (error) {
      console.error('Error sending payment failure email:', error)
      return false
    }
  }

  // Payment action required email
  async sendPaymentActionRequired(
    userId: string,
    invoice: any
  ): Promise<boolean> {
    try {
      const user = await this.getUserDetails(userId)
      if (!user?.email) return false

      const amount = (invoice.amount_due / 100).toFixed(2)
      const currency = invoice.currency.toUpperCase()
      const invoiceUrl = invoice.hosted_invoice_url

      const subject = 'Payment Authentication Required'
      const html = this.generatePaymentActionRequiredHTML(user, amount, currency, invoiceUrl)
      const text = this.generatePaymentActionRequiredText(user, amount, currency, invoiceUrl)

      return await this.provider.sendEmail(user.email, subject, html, text)
    } catch (error) {
      console.error('Error sending payment action required email:', error)
      return false
    }
  }

  // Trial ending email
  async sendTrialEnding(
    userId: string,
    subscription: any
  ): Promise<boolean> {
    try {
      const user = await this.getUserDetails(userId)
      if (!user?.email) return false

      const trialEnd = new Date(subscription.trial_end * 1000)
      const nextBillingDate = trialEnd.toLocaleDateString()

      const subject = 'Your Free Trial Ends Soon'
      const html = this.generateTrialEndingHTML(user, nextBillingDate)
      const text = this.generateTrialEndingText(user, nextBillingDate)

      return await this.provider.sendEmail(user.email, subject, html, text)
    } catch (error) {
      console.error('Error sending trial ending email:', error)
      return false
    }
  }

  // Helper methods

  private async getUserDetails(userId: string) {
    if (!supabase) return null
    
    const { data: user } = await supabase
      .from('users')
      .select('email, full_name')
      .eq('id', userId)
      .single()

    return user
  }

  // HTML email templates

  private generatePaymentConfirmationHTML(
    user: any, 
    amount: string, 
    currency: string, 
    planName: string
  ): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Payment Confirmation</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #dc2626; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0; }
            .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Payment Successful!</h1>
            </div>
            <div class="content">
                <h2>Thank you, ${user.full_name || user.email}!</h2>
                <p>Your payment has been processed successfully. Here are the details:</p>
                
                <ul>
                    <li><strong>Plan:</strong> ${planName}</li>
                    <li><strong>Amount:</strong> ${currency} ${amount}</li>
                    <li><strong>Status:</strong> Active</li>
                    <li><strong>Email:</strong> ${user.email}</li>
                </ul>
                
                <p>Your COBRA AI subscription is now active and you have full access to all features.</p>
                
                <a href="${process.env.FRONTEND_URL}/dashboard" class="button">Access Dashboard</a>
                <a href="${process.env.FRONTEND_URL}/billing" class="button">Manage Subscription</a>
                
                <p>Need help? Contact our support team anytime.</p>
            </div>
            <div class="footer">
                <p>&copy; 2024 COBRA AI. All rights reserved.</p>
                <p>Secure payment processing by Stripe</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generatePaymentFailureHTML(
    user: any,
    amount: string,
    currency: string,
    error: string
  ): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Payment Failed</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #dc2626; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0; }
            .error { background: #fee; border: 1px solid #fcc; padding: 10px; border-radius: 5px; margin: 10px 0; }
            .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Payment Failed</h1>
            </div>
            <div class="content">
                <h2>Hello ${user.full_name || user.email},</h2>
                <p>We were unable to process your payment for COBRA AI. Please review the details below:</p>
                
                <ul>
                    <li><strong>Amount:</strong> ${currency} ${amount}</li>
                    <li><strong>Email:</strong> ${user.email}</li>
                </ul>
                
                <div class="error">
                    <strong>Error:</strong> ${error}
                </div>
                
                <p>To resolve this issue, please:</p>
                <ol>
                    <li>Check that your payment method is valid and has sufficient funds</li>
                    <li>Update your payment method if necessary</li>
                    <li>Try the payment again</li>
                </ol>
                
                <a href="${process.env.FRONTEND_URL}/billing" class="button">Update Payment Method</a>
                
                <p>If you continue to experience issues, please contact our support team.</p>
            </div>
            <div class="footer">
                <p>&copy; 2024 COBRA AI. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generatePaymentActionRequiredHTML(
    user: any,
    amount: string,
    currency: string,
    invoiceUrl: string
  ): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Payment Authentication Required</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #dc2626; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin: 10px 0; }
            .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Payment Authentication Required</h1>
            </div>
            <div class="content">
                <h2>Hello ${user.full_name || user.email},</h2>
                <p>Your bank requires additional authentication to complete your payment for COBRA AI.</p>
                
                <ul>
                    <li><strong>Amount:</strong> ${currency} ${amount}</li>
                    <li><strong>Email:</strong> ${user.email}</li>
                </ul>
                
                <div class="warning">
                    <strong>Action Required:</strong> Please complete the authentication process to continue your subscription.
                </div>
                
                <p>This is a security measure by your bank to protect your payment. Click the button below to complete the authentication:</p>
                
                <a href="${invoiceUrl}" class="button">Complete Payment Authentication</a>
                
                <p>If you don't complete this authentication, your subscription may be suspended.</p>
            </div>
            <div class="footer">
                <p>&copy; 2024 COBRA AI. All rights reserved.</p>
                <p>Secure payment processing by Stripe</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generateTrialEndingHTML(
    user: any,
    nextBillingDate: string
  ): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Trial Ending Soon</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #dc2626; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0; }
            .info { background: #e3f2fd; border: 1px solid #90caf9; padding: 10px; border-radius: 5px; margin: 10px 0; }
            .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Your Free Trial Ends Soon</h1>
            </div>
            <div class="content">
                <h2>Hello ${user.full_name || user.email},</h2>
                <p>Your COBRA AI free trial is ending soon. We hope you've enjoyed exploring our cybersecurity tools!</p>
                
                <div class="info">
                    <strong>Trial End Date:</strong> ${nextBillingDate}<br>
                    <strong>Next Billing:</strong> Your subscription will begin automatically unless you cancel.
                </div>
                
                <p>What happens next:</p>
                <ul>
                    <li>Your trial access continues until ${nextBillingDate}</li>
                    <li>After that, your subscription will begin automatically</li>
                    <li>You can cancel anytime before then with no charges</li>
                </ul>
                
                <a href="${process.env.FRONTEND_URL}/billing" class="button">Manage Subscription</a>
                <a href="${process.env.FRONTEND_URL}/dashboard" class="button">Continue Using COBRA AI</a>
                
                <p>Questions? Our support team is here to help!</p>
            </div>
            <div class="footer">
                <p>&copy; 2024 COBRA AI. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  // Plain text email templates (fallback)

  private generatePaymentConfirmationText(
    user: any,
    amount: string,
    currency: string,
    planName: string
  ): string {
    return `
Payment Confirmation - COBRA AI

Hello ${user.full_name || user.email},

Your payment has been processed successfully!

Details:
- Plan: ${planName}
- Amount: ${currency} ${amount}
- Status: Active
- Email: ${user.email}

Your COBRA AI subscription is now active. Access your dashboard at: ${process.env.FRONTEND_URL}/dashboard

Manage your subscription: ${process.env.FRONTEND_URL}/billing

Thank you for choosing COBRA AI!

---
COBRA AI Team
Secure payment processing by Stripe
    `
  }

  private generatePaymentFailureText(
    user: any,
    amount: string,
    currency: string,
    error: string
  ): string {
    return `
Payment Failed - COBRA AI

Hello ${user.full_name || user.email},

We were unable to process your payment for COBRA AI.

Details:
- Amount: ${currency} ${amount}
- Error: ${error}

To resolve this:
1. Check your payment method is valid
2. Update payment method if needed: ${process.env.FRONTEND_URL}/billing
3. Try the payment again

Contact support if issues persist.

---
COBRA AI Team
    `
  }

  private generatePaymentActionRequiredText(
    user: any,
    amount: string,
    currency: string,
    invoiceUrl: string
  ): string {
    return `
Payment Authentication Required - COBRA AI

Hello ${user.full_name || user.email},

Your bank requires additional authentication for your payment.

Amount: ${currency} ${amount}

Complete authentication here: ${invoiceUrl}

This is a security measure by your bank. Please complete authentication to continue your subscription.

---
COBRA AI Team
    `
  }

  private generateTrialEndingText(
    user: any,
    nextBillingDate: string
  ): string {
    return `
Trial Ending Soon - COBRA AI

Hello ${user.full_name || user.email},

Your COBRA AI free trial ends on ${nextBillingDate}.

After that date, your subscription will begin automatically unless you cancel.

Manage your subscription: ${process.env.FRONTEND_URL}/billing
Continue using COBRA AI: ${process.env.FRONTEND_URL}/dashboard

Questions? Contact our support team.

---
COBRA AI Team
    `
  }
}

// Export singleton instance
export const emailService = new EmailService()
