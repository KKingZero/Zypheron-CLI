import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App.tsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
      <Toaster 
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#161b22',
            color: '#f0f6fc',
            border: '1px solid #21262d',
          },
          success: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#161b22',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#161b22',
            },
          },
        }}
      />
    </BrowserRouter>
  </React.StrictMode>,
) 

// Register service worker for PWA installability and offline support (only in production)
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
	window.addEventListener('load', () => {
		navigator.serviceWorker.register('/sw.js', {
			scope: '/'
		}).then((registration) => {
			console.log('Service Worker registered successfully:', registration.scope);
			
			// Check for updates
			registration.addEventListener('updatefound', () => {
				console.log('New service worker version found');
			});
		}).catch((error) => {
			console.error('Service worker registration failed:', error);
		});
	});
}