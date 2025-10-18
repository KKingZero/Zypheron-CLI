import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate, useSearchParams } from 'react-router-dom';

const LoginPage: React.FC = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isSignUp, setIsSignUp] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const { signIn, signUp, user } = useAuth();
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();

    // Check account status after login and redirect accordingly
    useEffect(() => {
        if (user) {
            const checkStatusAndRedirect = async () => {
                try {
                    const response = await fetch('/api/billing/subscription', {
                        headers: {
                            'Authorization': `Bearer ${user.access_token || ''}`
                        }
                    });
                    
                    const data = await response.json();
                    const planName = data?.accessLevel?.plan_name?.toLowerCase();
                    
                    if (planName && ['light', 'pro', 'enterprise', 'super'].includes(planName)) {
                        // User has subscription, go to dashboard
                        navigate('/dashboard');
                    } else {
                        // No subscription, redirect to billing
                        window.location.href = 'https://cobraai.dev/billing';
                    }
                } catch (error) {
                    console.error('Failed to check subscription status');
                    navigate('/dashboard'); // Fallback to dashboard
                }
            };
            
            checkStatusAndRedirect();
        }
    }, [user, navigate]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        try {
            const { error: authError } = isSignUp 
                ? await signUp(email, password)
                : await signIn(email, password);

            if (authError) {
                setError(authError.message);
            }
        } catch (err: any) {
            setError(err.message || 'An unexpected error occurred.');
        } finally {
            setLoading(false);
        }
    };

    // Show loading while redirecting
    if (user) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-black text-white">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-zypheron-500 mx-auto mb-4"></div>
                    <p>Checking your account status...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex items-center justify-center min-h-screen bg-black text-white">
            <div className="w-full max-w-sm bg-gray-800 rounded-xl p-8 mx-4" style={{ backgroundColor: '#2a2a2a' }}>
                <div className="text-center mb-8">
                    {/* Zypheron Logo */}
                    <div className="mb-6">
                        <img 
                            src="/Zypheron1.jpg" 
                            alt="Zypheron Logo" 
                            className="w-16 h-16 mx-auto mb-3"
                        />
                        <div className="text-xs text-zypheron-500 font-medium tracking-wider">Zypheron</div>
                    </div>
                    
                    <h1 className="text-2xl font-medium text-white mb-2">Welcome Back!</h1>
                    <p className="text-gray-400 text-sm">
                        Sign in to continue to Zypheron.
                    </p>
                </div>
                
                <form onSubmit={handleSubmit} className="space-y-5">
                    <div>
                        <label className="block text-sm font-medium text-white mb-2">Email</label>
                        <input 
                            type="email" 
                            placeholder="your@email.com" 
                            value={email} 
                            onChange={(e) => setEmail(e.target.value)} 
                            required 
                            className="w-full px-4 py-3 bg-gray-700 border-0 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-zypheron-500 focus:outline-none"
                            style={{ backgroundColor: '#1a1a1a' }}
                        />
                    </div>
                    
                    <div>
                        <label className="block text-sm font-medium text-white mb-2">Password</label>
                        <input 
                            type="password" 
                            placeholder="••••••••" 
                            value={password} 
                            onChange={(e) => setPassword(e.target.value)} 
                            required 
                            className="w-full px-4 py-3 bg-gray-700 border-0 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-zypheron-500 focus:outline-none"
                            style={{ backgroundColor: '#1a1a1a' }}
                        />
                    </div>
                    
                    {error && <p className="text-zypheron-500 text-sm text-center">{error}</p>}
                    
                    <button 
                        type="submit" 
                        className="w-full bg-zypheron-600 hover:bg-zypheron-700 text-white font-medium py-3 rounded-lg transition-colors disabled:opacity-50 mt-6" 
                        disabled={loading}
                        style={{ backgroundColor: '#dc2626' }}
                    >
                        {loading ? 'Processing...' : (isSignUp ? 'Sign Up' : 'Continue')}
                    </button>
                </form>
                
                <div className="text-center mt-6">
                    <button 
                        onClick={() => setIsSignUp(!isSignUp)} 
                        className="text-sm text-gray-400 hover:text-gray-300 transition-colors"
                    >
                        {isSignUp ? 'Already have an account? Sign In' : "Don't have an account? Create one"}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;