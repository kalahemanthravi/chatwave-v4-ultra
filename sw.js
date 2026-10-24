// ChatWave Ultra Service Worker
// Handles background push display when tab is not focused

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', () => self.clients.claim());

// Listen for push events (from the app via postMessage)
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SHOW_NOTIFICATION') {
    const { title, body, icon, tag } = event.data;
    self.registration.showNotification(title, {
      body,
      icon: icon || '/icon.png',
      badge: '/icon.png',
      tag: tag || 'chatwave-msg',
      renotify: true,
      vibrate: [200, 100, 200],
      data: { url: self.location.origin }
    });
  }
});

// Clicking notification focuses the app tab
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (client.url.startsWith(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow('/');
    })
  );
});
