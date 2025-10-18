import React, { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

interface SEOOptimizerProps {
  title?: string
  description?: string
  keywords?: string
  canonicalUrl?: string
  ogImage?: string
}

const SEOOptimizer: React.FC<SEOOptimizerProps> = ({
  title,
  description,
  keywords,
  canonicalUrl,
  ogImage
}) => {
  const location = useLocation()

  useEffect(() => {
    // Update page title
    if (title) {
      document.title = `${title} | Zypheron - Advanced AI Cybersecurity Assistant`
    }

    // Update meta description
    if (description) {
      const metaDescription = document.querySelector('meta[name="description"]')
      if (metaDescription) {
        metaDescription.setAttribute('content', description)
      }
    }

    // Update meta keywords
    if (keywords) {
      const metaKeywords = document.querySelector('meta[name="keywords"]')
      if (metaKeywords) {
        metaKeywords.setAttribute('content', keywords)
      }
    }

    // Update canonical URL
    if (canonicalUrl) {
      let canonicalLink = document.querySelector('link[rel="canonical"]')
      if (!canonicalLink) {
        canonicalLink = document.createElement('link')
        canonicalLink.setAttribute('rel', 'canonical')
        document.head.appendChild(canonicalLink)
      }
      canonicalLink.setAttribute('href', canonicalUrl)
    }

    // Update Open Graph meta tags
    if (title) {
      updateOrCreateMeta('property', 'og:title', `${title} | Zypheron - AI Cybersecurity Assistant`)
    }
    if (description) {
      updateOrCreateMeta('property', 'og:description', description)
    }
    if (ogImage) {
      updateOrCreateMeta('property', 'og:image', ogImage)
    }
    if (canonicalUrl) {
      updateOrCreateMeta('property', 'og:url', canonicalUrl)
    }

    // Update Twitter Card meta tags
    if (title) {
      updateOrCreateMeta('name', 'twitter:title', `${title} | Zypheron - AI Cybersecurity Assistant`)
    }
    if (description) {
      updateOrCreateMeta('name', 'twitter:description', description)
    }
    if (ogImage) {
      updateOrCreateMeta('property', 'twitter:image', ogImage)
    }

    // Track page view for analytics (placeholder for Google Analytics)
    trackPageView(location.pathname + location.search)

    // Add structured data for current page
    addPageStructuredData(title, description, canonicalUrl)

  }, [title, description, keywords, canonicalUrl, ogImage, location])

  // Helper function to update or create meta tags
  const updateOrCreateMeta = (attribute: string, selector: string, content: string) => {
    let meta = document.querySelector(`meta[${attribute}="${selector}"]`)
    if (!meta) {
      meta = document.createElement('meta')
      meta.setAttribute(attribute, selector)
      document.head.appendChild(meta)
    }
    meta.setAttribute('content', content)
  }

  // Enhanced analytics tracking function - 3rd party tracking disabled for privacy
  const trackPageView = (page: string) => {
    // Check privacy settings - disable 3rd party tracking
    const disableTracking = import.meta.env.VITE_DISABLE_3RD_PARTY_TRACKING === 'true'
    const blockExternalAnalytics = import.meta.env.VITE_BLOCK_EXTERNAL_ANALYTICS === 'true'
    const hcfsClintBlock = import.meta.env.VITE_HCFS_CLINT_BLOCK === 'true'

    // Skip Google Analytics completely when privacy settings are enabled
    if (disableTracking || blockExternalAnalytics || hcfsClintBlock) {
      // Google Analytics disabled for privacy
      console.log('[Privacy] External analytics tracking blocked by privacy settings')
    }

    // Internal analytics only - send to your own analytics endpoint with enhanced data
    if (typeof fetch !== 'undefined' && !hcfsClintBlock) {
      fetch('/api/analytics/pageview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          page,
          title: document.title,
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          referrer: document.referrer,
          keywords: extractKeywordsFromPage(page),
          category: getCybersecurityCategory(page),
          language: navigator.language,
          screen: `${screen.width}x${screen.height}`,
          viewport: `${window.innerWidth}x${window.innerHeight}`,
          privacy_mode: 'internal_only',
          hcfs_clint_blocked: hcfsClintBlock
        })
      }).catch(() => {
        // Silently fail - analytics shouldn't break the app
      })
    }
  }

  // Helper function to extract AI hacking keyword based on page
  const getAIHackingKeyword = (page: string): string => {
    if (page.includes('pentest')) return 'pentest ai'
    if (page.includes('red-team')) return 'red team ai'
    if (page.includes('chat') || page.includes('ai')) return 'ai hacking'
    if (page.includes('cyber') || page.includes('security')) return 'ai cyber'
    return 'cyber'
  }

  // Helper function to categorize cybersecurity content
  const getCybersecurityCategory = (page: string): string => {
    if (page.includes('pentest')) return 'penetration-testing'
    if (page.includes('red-team')) return 'red-team-operations'
    if (page.includes('recon')) return 'reconnaissance'
    if (page.includes('ioc')) return 'threat-intelligence'
    if (page.includes('chat')) return 'ai-assistant'
    return 'cybersecurity-tools'
  }

  // Helper function to determine user intent
  const getUserIntent = (page: string): string => {
    if (page.includes('login') || page.includes('billing')) return 'conversion'
    if (page.includes('chat')) return 'engagement'
    if (page.includes('tools') || page.includes('pentest')) return 'usage'
    if (page === '/') return 'discovery'
    return 'exploration'
  }

  // Helper function to extract keywords from current page
  const extractKeywordsFromPage = (page: string): string[] => {
    const baseKeywords = ['ai hacking', 'pentest ai', 'ai cyber', 'red team ai', 'red team', 'cyber']
    const pageSpecificKeywords: { [key: string]: string[] } = {
      '/chat': ['ai chat', 'cybersecurity chatbot', 'ai assistant'],
      '/pentest': ['penetration testing', 'automated pentest', 'ai vulnerability scanner'],
      '/command-control': ['command control', 'c2', 'post-exploitation', 'lateral movement', 'privilege escalation'],
      '/red-team': ['red team operations', 'offensive security', 'attack simulation']
    }
    
    return [...baseKeywords, ...(pageSpecificKeywords[page] || [])]
  }

  // Enhanced page-specific structured data
  const addPageStructuredData = (title?: string, description?: string, url?: string) => {
    const pageType = getPageType(location.pathname)
    const structuredData: any = {
      '@context': 'https://schema.org',
      '@type': pageType,
      'name': title || document.title,
      'description': description || 'Advanced AI-powered cybersecurity assistant for professional penetration testing and red team operations',
      'url': url || window.location.href,
      'isPartOf': {
        '@type': 'WebSite',
        'name': 'Zypheron - AI Cybersecurity Assistant',
        'url': 'https://cobraai.dev'
      },
      'dateModified': new Date().toISOString(),
      'provider': {
        '@type': 'Organization',
        'name': 'Zypheron Team',
        'url': 'https://cobraai.dev'
      },
      'keywords': extractKeywordsFromPage(location.pathname).join(', '),
      'category': getCybersecurityCategory(location.pathname),
      'audience': {
        '@type': 'Audience',
        'audienceType': ['Cybersecurity Professionals', 'Penetration Testers', 'Red Team Operators', 'Security Researchers']
      }
    }

    // Add page-specific properties
    if (pageType === 'SoftwareTool') {
      structuredData['applicationCategory'] = 'SecurityApplication'
      structuredData['operatingSystem'] = 'Web Browser'
    }

    // Remove existing page structured data
    const existingScript = document.querySelector('script[data-page-schema]')
    if (existingScript) {
      existingScript.remove()
    }

    // Add new structured data
    const script = document.createElement('script')
    script.type = 'application/ld+json'
    script.setAttribute('data-page-schema', 'true')
    script.textContent = JSON.stringify(structuredData)
    document.head.appendChild(script)
  }

  // Helper function to determine page type for structured data
  const getPageType = (pathname: string): string => {
    if (pathname.includes('pentest') || pathname.includes('tools') || pathname.includes('scanner')) {
      return 'SoftwareTool'
    }
    if (pathname.includes('chat')) {
      return 'WebApplication'
    }
    if (pathname.includes('blog') || pathname.includes('guides')) {
      return 'Article'
    }
    return 'WebPage'
  }

  // Preload critical resources for better performance - privacy respecting
  useEffect(() => {
    const preloadCriticalResources = () => {
      const disableTracking = import.meta.env.VITE_DISABLE_3RD_PARTY_TRACKING === 'true'
      const hcfsClintBlock = import.meta.env.VITE_HCFS_CLINT_BLOCK === 'true'

      // Skip external font preloading when privacy settings are enabled
      if (disableTracking || hcfsClintBlock) {
        console.log('[Privacy] External font preloading blocked by privacy settings')
      }

      // Preload critical API endpoints (internal only)
      const apiEndpoints = [
        '/api/user/health',
        '/api/chat/models'
      ]

      apiEndpoints.forEach(endpoint => {
        const link = document.createElement('link')
        link.rel = 'dns-prefetch'
        link.href = new URL(endpoint, window.location.origin).origin
        document.head.appendChild(link)
      })
    }

    preloadCriticalResources()
  }, [])

  return null
}

// Enhanced predefined SEO configurations targeting specific keywords
export const seoConfigs = {
  home: {
    title: 'AI Hacking & Red Team Cybersecurity Assistant',
    description: 'Professional AI-powered hacking toolkit for penetration testing, red team operations, and cybersecurity research. Advanced pentest AI with automated vulnerability discovery, cyber threat analysis, and AI-driven security assessment tools.',
    keywords: 'ai hacking, pentest ai, ai cyber, red team ai, red team, cyber, cybersecurity AI, AI penetration testing, automated hacking, artificial intelligence security, AI cyber tools, machine learning hacking, AI vulnerability scanner, intelligent pentesting, AI-powered red team, cyber AI assistant',
    canonicalUrl: 'https://cobraai.dev/',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  chat: {
    title: 'AI Hacking Chat Interface - Cybersecurity AI Assistant',
    description: 'Interact with advanced AI models specialized in cybersecurity, penetration testing, and red team operations. AI-powered hacking assistant for professional security analysis and automated threat assessment.',
    keywords: 'ai hacking chat, cybersecurity ai assistant, pentest ai chat, red team ai, ai cyber security, automated hacking, ai penetration testing assistant, intelligent security analysis',
    canonicalUrl: 'https://cobraai.dev/chat',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  pentest: {
    title: 'AI Penetration Testing Tools - Advanced Pentest AI Platform',
    description: 'Professional AI-powered penetration testing suite with automated vulnerability assessment, intelligent exploit generation, and advanced red team capabilities. Revolutionary pentest AI for cybersecurity professionals.',
    keywords: 'pentest ai, ai penetration testing, automated pentest, ai vulnerability scanner, intelligent pentesting, ai hacking tools, red team ai, automated exploitation, ai security testing, cyber ai assessment',
    canonicalUrl: 'https://cobraai.dev/pentest',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  tools: {
    title: 'AI Hacking Tools & Red Team Cybersecurity Suite',
    description: 'Comprehensive collection of AI-enhanced cybersecurity tools for reconnaissance, scanning, and threat analysis. Professional AI hacking toolkit for red team operations and penetration testing.',
    keywords: 'ai hacking tools, red team ai, cyber ai tools, ai security scanner, automated recon tools, ai cyber reconnaissance, intelligent security tools, red team automation, ai cybersecurity suite',
    canonicalUrl: 'https://cobraai.dev/command-control',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  mobileChat: {
    title: 'Mobile AI Hacking Assistant - Cybersecurity on the Go',
    description: 'Mobile-optimized AI hacking assistant for cybersecurity professionals. Access advanced pentest AI, red team tools, and cyber security analysis from any mobile device.',
    keywords: 'mobile ai hacking, mobile pentest ai, mobile cybersecurity, mobile red team, mobile cyber tools, mobile security assistant, portable ai hacking',
    canonicalUrl: 'https://cobraai.dev/mobile-chat',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  login: {
    title: 'Login to Zypheron - Professional Cybersecurity Assistant',
    description: 'Access your Zypheron account for advanced AI cybersecurity tools and professional security automation. Secure login for cybersecurity professionals.',
    keywords: 'cobra ai login, cybersecurity account, ai hacking access, pentest ai login, red team access, cyber security tools login',
    canonicalUrl: 'https://cobraai.dev/login',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  billing: {
    title: 'Zypheron Pricing - Professional AI Cybersecurity Plans',
    description: 'Choose your Zypheron plan for advanced AI cybersecurity capabilities and professional security automation. Flexible pricing for security professionals.',
    keywords: 'cobra ai pricing, ai hacking plans, pentest ai cost, cybersecurity subscription, red team pricing, ai cyber tools pricing',
    canonicalUrl: 'https://cobraai.dev/billing',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  },
  freeTrial: {
    title: 'Free Trial - Experience AI Hacking & Cybersecurity Tools',
    description: 'Start your free trial of Zypheron and experience advanced AI cybersecurity capabilities and professional security automation at no cost.',
    keywords: 'free ai hacking trial, pentest ai free trial, cybersecurity tools trial, red team free access, ai cyber trial, free cybersecurity ai',
    canonicalUrl: 'https://cobraai.dev/free-trial',
    ogImage: 'https://cobraai.dev/cobra-preview.png'
  }
}

export default SEOOptimizer 