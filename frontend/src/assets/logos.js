/**
 * Zypheron Logo Assets
 * Centralized logo path exports for React components
 */

// Public logo paths (served by Vite dev server)
export const ZYPHERON_LOGOS = {
  // Main detailed logo
  main: '/Zypheron1.jpg',
  
  // Small icon for headers/navigation
  icon: '/ZypheronX.jpg',
  
  // Alternative paths for assets directory (if needed for imports)
  mainAsset: '/src/ZypheronX.jpg',
  iconAsset: '/ZypheronX.jpg'
}

// Logo specifications
export const LOGO_SPECS = {
  colors: {
    primary: '#16a34a',      // Main Zypheron green
    dark: '#1a1a1a',         // Dark accents
    secondary: '#15803d'     // Secondary green
  },
  
  sizes: {
    main: { width: 800, height: 800 },
    icon: { width: 200, height: 200 }
  },
  
  usage: {
    main: ['welcome screens', 'hero sections', 'main branding'],
    icon: ['headers', 'navigation', 'favicon', 'small spaces']
  }
}

// Component usage examples
export const USAGE_EXAMPLES = {
  mainLogo: `<img src="/Zypheron1.jpg" alt="Zypheron" className="w-48 h-48" />`,
  iconLogo: `<img src="/ZypheronX.jpg" alt="Zypheron Logo" className="w-8 h-8" />`,
  reactImport: `import { ZYPHERON_LOGOS } from '@/assets/logos'`
}

// Default exports for convenience
export default ZYPHERON_LOGOS 