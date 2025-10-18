import React, { useEffect, useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useSearchParams, useNavigate } from 'react-router-dom';

const WelcomePage: React.FC = () => {
    const [searchParams] = useSearchParams();
    const { user } = useAuth();
    const navigate = useNavigate();
    const [planInfo, setPlanInfo] = useState<string | null>(null);

    useEffect(() => {
        const plan = searchParams.get('plan');
        const planName = searchParams.get('plan_name');
        
        if (plan && planName) {
            setPlanInfo(decodeURIComponent(planName));
        }
    }, [searchParams]);

    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
            <div className="text-center max-w-md">
                {/* Zypheron Success Logo */}
                <div className="w-20 h-20 bg-green-500 rounded-full flex items-center justify-center mx-auto mb-6">
                    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
                        {/* Success checkmark with zypheron elements */}
                        <path d="M15 20L18 23L25 16" stroke="white" strokeWidth="3" fill="none"/>
                        {/* Small zypheron head outline */}
                        <path d="M20 8C22 8 24 9 24 11C24 12 23 13 22 13L21 15C21 16 20 16 20 16C20 16 19 16 19 15L18 13C17 13 16 12 16 11C16 9 18 8 20 8Z" fill="white" opacity="0.3"/>
                    </svg>
                </div>
                
                <h1 className="text-3xl font-bold mb-4">
                    Welcome to Zypheron{planInfo ? ` ${planInfo}` : ''}!
                </h1>
                
                <p className="text-gray-300 mb-8">
                    Your payment was successful. Please log in to access your cybersecurity tools and features.
                </p>
                
                {!user ? (
                    <button
                        onClick={() => navigate('/login')}
                        className="bg-zypheron-500 hover:bg-zypheron-600 text-white font-bold py-3 px-8 rounded-lg transition-colors"
                    >
                        Login to Continue
                    </button>
                ) : (
                    <div>
                        <p className="text-green-400 mb-4">You're already logged in!</p>
                        <button
                            onClick={() => navigate('/billing')}
                            className="bg-zypheron-500 hover:bg-zypheron-600 text-white font-bold py-3 px-8 rounded-lg transition-colors"
                        >
                            Continue to Billing
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default WelcomePage;
