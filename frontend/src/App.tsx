import React, { Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'

// ========================================
// EAGER LOADED (Main Dashboard - Always Available)
// ========================================
// Chat is NOT lazy loaded - user specified it needs to be in memory server-side
import Chat from './app/pages/Chat'
import LoginPage from './shared/pages/Login' // Auth page - load immediately

// ========================================
// LAZY LOADED PAGES (Code Split for Performance)
// ========================================
// These pages are loaded on-demand to reduce initial bundle size
const CommandControl = React.lazy(() => import('./app/pages/CommandControl'))
const RedTeamOps = React.lazy(() => import('./app/pages/RedTeamOps'))
const Settings = React.lazy(() => import('./app/pages/Settings'))
const MobileChat = React.lazy(() => import('./app/pages/MobileChat'))

// Legal pages - rarely accessed, safe to lazy load
const WelcomePage = React.lazy(() => import('./shared/pages/WelcomePage'))
const TermsOfService = React.lazy(() => import('./shared/pages/TermsOfService'))
const TermsOfUse = React.lazy(() => import('./shared/pages/TermsOfUse'))

// Billing page - accessed occasionally
const Billing = React.lazy(() => import('./pages/Billing'))

// Other imports (utilities, contexts, etc.)
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { ChatProvider } from './contexts/ChatContext'
import ProtectedRoute from './components/ProtectedRoute'
import DevModeToggle from './components/DevModeToggle'
import DevDebugInfo from './components/DevDebugInfo'
import DevPlanSelector from './components/DevPlanSelector'
import ErrorBoundary from './components/ErrorBoundary'
import { ChunkLoader } from './components/LoadingSpinner'
import { isLocalhost, isDevModeEnabled } from './utils/devMode'
import { useRBACSubscriptionAccess } from './hooks/useRBACSubscriptionAccess'
import { setupOfflineSupport } from './utils/networkStatus'

// Smart routing component that handles authentication redirects
const AppRoutes = () => {
  const { user, loading, isDeveloperBypassActive, userPermissions } = useAuth()
  const { hasAccess, loading: subscriptionLoading } = useRBACSubscriptionAccess()
  
  // Dev mode bypass for routing
  const devModeBypass = isDevModeEnabled()

  // Show loading spinner while checking authentication state and subscription
  // Following Apple HIG: Clear feedback and appropriate wait times
  if (loading || subscriptionLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-terminal-bg text-terminal-text" role="main">
        <section className="text-center" aria-live="polite" aria-label="Loading application">
          <div 
            className="animate-spin rounded-full h-12 w-12 border-b-2 border-zypheron-500 mx-auto mb-4"
            role="status"
            aria-label="Loading spinner"
          ></div>
          <p className="text-terminal-muted text-base" role="status">
            {loading ? 'Loading Zypheron...' : 'Verifying subscription...'}
          </p>
        </section>
      </div>
    )
  }

  return (
    <Routes>
      {/* App Root - Direct to login, billing, or dashboard based on auth and subscription state */}
      <Route path="/" element={
        devModeBypass ? <Navigate to="/dashboard" replace /> :
        !user ? <Navigate to="/login" replace /> :
        !hasAccess ? <Navigate to="/billing" replace /> :
        <Navigate to="/dashboard" replace />
      } />
      
      {/* Authentication Routes */}
      <Route 
        path="/login" 
        element={
          user ? <Navigate to="/dashboard" replace /> : <LoginPage />
        } 
      />
      
      {/* Welcome page for post-payment flow */}
      <Route path="/welcome" element={
        <Suspense fallback={<ChunkLoader page="Welcome" />}>
          <WelcomePage />
        </Suspense>
      } />
      


      {/* Protected App Routes - Dashboard and Tools */}
      <Route element={<ProtectedRoute />}>
        {/* Main Dashboard - Chat Interface - NOT LAZY LOADED */}
        <Route path="/dashboard" element={<Chat />} />
        <Route path="/chat" element={<Chat />} />
        <Route path="/mobile-chat" element={
          <Suspense fallback={<ChunkLoader page="Mobile Chat" fullHeight={false} />}>
            <MobileChat />
          </Suspense>
        } />
        
        {/* Security Tools - LAZY LOADED for performance */}
        <Route path="/command-control" element={
          <Layout>
            <Suspense fallback={<ChunkLoader page="Command & Control" fullHeight={false} />}>
              <CommandControl />
            </Suspense>
          </Layout>
        } />
        <Route path="/red-team-ops" element={
          <Layout>
            <Suspense fallback={<ChunkLoader page="Red Team Operations" fullHeight={false} />}>
              <RedTeamOps />
            </Suspense>
          </Layout>
        } />
        
        {/* Account Management - LAZY LOADED */}
        <Route path="/settings" element={
          <Suspense fallback={<ChunkLoader page="Settings" />}>
            <Settings />
          </Suspense>
        } />
      </Route>
      
      {/* Billing - LAZY LOADED */}
      <Route path="/billing" element={
        <Suspense fallback={<ChunkLoader page="Billing" />}>
          <Billing />
        </Suspense>
      } />

      {/* Legal Pages - LAZY LOADED */}
      <Route path="/terms-of-service" element={
        <Suspense fallback={<ChunkLoader page="Terms of Service" />}>
          <TermsOfService />
        </Suspense>
      } />
      <Route path="/terms-of-use" element={
        <Suspense fallback={<ChunkLoader page="Terms of Use" />}>
          <TermsOfUse />
        </Suspense>
      } />

                    {/* Catch-all route - redirect unknown paths based on auth and subscription state */}
      <Route path="*" element={
        devModeBypass ? <Navigate to="/dashboard" replace /> :
        !user ? <Navigate to="/login" replace /> :
        !hasAccess ? <Navigate to="/billing" replace /> :
        <Navigate to="/dashboard" replace />
      } />
    </Routes>
  )
}

function App() {
  const [showPlanSelector, setShowPlanSelector] = React.useState(false)

  // Setup offline support
  React.useEffect(() => {
    const cleanup = setupOfflineSupport()
    return cleanup
  }, [])

  const handleTogglePlanSelector = () => {
    setShowPlanSelector(!showPlanSelector)
  }

  const handleClosePlanSelector = () => {
    setShowPlanSelector(false)
  }

  return (
    <ErrorBoundary>
      <AuthProvider>
        <ErrorBoundary>
          <ChatProvider>
            <ErrorBoundary>
              <div className="min-h-screen bg-terminal-bg text-terminal-text overflow-x-hidden w-full max-w-full">
                {/* Accessibility: Skip to main content link - Apple HIG principle */}
                <a 
                  href="#main-content" 
                  className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-zypheron-500 text-white px-4 py-2 rounded-lg z-50 min-h-[44px] min-w-[44px] flex items-center justify-center"
                  aria-label="Skip to main content"
                >
                  Skip to main content
                </a>
                
                {/* Main application content - Clear hierarchy following Apple HIG */}
                <main id="main-content" role="main" aria-label="Zypheron Cybersecurity Assistant">
                  <AppRoutes />
                </main>
                
                {/* Development tools - Only visible in development */}
                <aside role="complementary" aria-label="Development tools">
                  <DevModeToggle />
                  <DevDebugInfo onTogglePlanSelector={handleTogglePlanSelector} />
                  <DevPlanSelector isVisible={showPlanSelector} onClose={handleClosePlanSelector} />
                </aside>
              </div>
            </ErrorBoundary>
          </ChatProvider>
        </ErrorBoundary>
      </AuthProvider>
    </ErrorBoundary>
  )
}

export default App 