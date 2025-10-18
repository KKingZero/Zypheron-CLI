#!/usr/bin/env node
/**
 * 🔧 Dev Mode Auto-Fix Script for Zypheron
 * Automatically enables dev mode for localhost development
 */

console.log('🔧 Zypheron Dev Mode Auto-Fix\n')

// Check if we're running on localhost
const isLocalhost = () => {
  try {
    if (typeof window !== 'undefined') {
      const hostname = window.location.hostname
      return hostname === 'localhost' || hostname === '127.0.0.1'
    }
  } catch (e) {
    // Running in Node.js
    return true
  }
  return false
}

// Auto-enable dev mode
const enableDevMode = () => {
  if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
    // Browser environment
    window.COBRA_DEV_MODE = true
    localStorage.setItem('COBRA_DEV_MODE', 'true')
    console.log('✅ Dev mode ENABLED in browser')
    console.log('🔄 Please refresh the page to apply changes')
  } else {
    // Node.js environment
    console.log('✅ Dev mode script ready')
    console.log('📋 Instructions:')
    console.log('  1. Open browser to http://localhost:5173')
    console.log('  2. Dev mode will auto-enable on localhost')
    console.log('  3. Look for green "Dev Mode ON" toggle in bottom-right')
    console.log('  4. Chat should work without authentication')
  }
}

// Environment checks
const checkEnvironment = () => {
  console.log('🔍 Environment Check:')
  console.log(`  - NODE_ENV: ${process.env.NODE_ENV || 'undefined'}`)
  console.log(`  - Port: ${process.env.PORT || '3001'}`)
  console.log(`  - Dev bypass: ${process.env.ALLOW_LOCALHOST_DEV || 'undefined'}`)
  console.log('')
}

// Main execution
const main = () => {
  checkEnvironment()
  enableDevMode()
  
  console.log('\n🎯 What was fixed:')
  console.log('  ✅ Dev mode now auto-enables on localhost')
  console.log('  ✅ Chat routes use enhanced auth middleware')
  console.log('  ✅ Backend dev environment configured')
  console.log('  ✅ Auth bypass works internally')
  
  console.log('\n🚀 Next steps:')
  console.log('  1. Start servers: npm run dev')
  console.log('  2. Open http://localhost:5173')  
  console.log('  3. Check bottom-right for "Dev Mode" toggle')
  console.log('  4. Try using chat - should work without login!')
  
  console.log('\n📝 For web version:')
  console.log('  - Web uses Supabase authentication')
  console.log('  - Deploy with proper environment variables')
  console.log('  - See NETLIFY_DEPLOYMENT_GUIDE.md for details')
}

// Run if called directly
if (require.main === module) {
  main()
}

module.exports = { enableDevMode, checkEnvironment, isLocalhost }
