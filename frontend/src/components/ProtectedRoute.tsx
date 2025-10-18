import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useRBACSubscriptionAccess } from '../hooks/useRBACSubscriptionAccess';
import { isDevModeEnabled, shouldBypassAuth, hasUnlimitedAccess } from '../utils/devMode';

const ProtectedRoute: React.FC = () => {
  const { user, loading: authLoading } = useAuth();
  const { hasAccess, loading: subscriptionLoading, needsUpgrade } = useRBACSubscriptionAccess();

  // Dev mode bypass - allow access if dev mode is enabled on localhost
  const devModeBypass = isDevModeEnabled();
  const devModeFullAccess = devModeBypass && hasUnlimitedAccess();
  
  // Show loading while checking authentication and subscription
  if (authLoading || subscriptionLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-terminal-bg text-terminal-text">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
          <p className="text-xl">
            {devModeBypass ? 'Loading dev environment...' : 'Verifying your access...'}
          </p>
        </div>
      </div>
    );
  }

  // Dev mode bypass - skip all checks if dev mode is enabled
  if (devModeBypass) {
    console.log('🚀 DEV MODE: Full bypass enabled - allowing access to all features')
    return <Outlet />;
  }

  // Production checks - require authentication and subscription
  // Redirect to login if not authenticated
  if (!user) {
    return <Navigate to="/login" replace />;
  }

  // Special handling for billing page - allow access even without subscription in dev mode
  // This ensures users can always access billing to "purchase" or test subscriptions
  if ((!hasAccess || needsUpgrade) && window.location.pathname !== '/billing') {
    return <Navigate to="/billing" replace />;
  }
  
  // If on billing page without access, still allow it (billing should handle its own access)
  if (window.location.pathname === '/billing') {
    console.log('💳 BILLING: Allowing access to billing page for subscription management')
    return <Outlet />;
  }

  // User is authenticated and has valid subscription - allow access
  return <Outlet />;
};

export default ProtectedRoute; 