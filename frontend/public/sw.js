const CACHE_NAME = 'cobraai-cache-v2';
const PRECACHE_URLS = [
	'/',
	'/index.html',
	'/manifest.json',
	'/ZypheronX.jpg'
];

// Install event - precache essential resources
self.addEventListener('install', (event) => {
	console.log('Service Worker installing...');
	event.waitUntil(
		caches.open(CACHE_NAME)
			.then((cache) => {
				console.log('Precaching app shell');
				return cache.addAll(PRECACHE_URLS);
			})
			.then(() => {
				console.log('Service Worker installed successfully');
				return self.skipWaiting();
			})
			.catch((error) => {
				console.error('Service Worker installation failed:', error);
			})
	);
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
	console.log('Service Worker activating...');
	event.waitUntil(
		caches.keys()
			.then((cacheNames) => {
				return Promise.all(
					cacheNames.map((cacheName) => {
						if (cacheName !== CACHE_NAME) {
							console.log('Deleting old cache:', cacheName);
							return caches.delete(cacheName);
						}
					})
				);
			})
			.then(() => {
				console.log('Service Worker activated');
				return self.clients.claim();
			})
	);
});

// Fetch event - network first, cache fallback strategy
self.addEventListener('fetch', (event) => {
	const { request } = event;
	
	// Skip non-GET requests and external URLs
	if (request.method !== 'GET' || !request.url.startsWith(self.location.origin)) {
		return;
	}

	event.respondWith(
		fetch(request)
			.then((response) => {
				// Only cache successful responses
				if (response.status === 200) {
					const responseClone = response.clone();
					caches.open(CACHE_NAME)
						.then((cache) => cache.put(request, responseClone))
						.catch((error) => console.warn('Cache put failed:', error));
				}
				return response;
			})
			.catch(() => {
				// Fallback to cache, then to offline page
				return caches.match(request)
					.then((cached) => {
						if (cached) {
							return cached;
						}
						// Fallback to main page for navigation requests
						if (request.mode === 'navigate') {
							return caches.match('/');
						}
						throw new Error('No cached version available');
					});
			})
	);
});


