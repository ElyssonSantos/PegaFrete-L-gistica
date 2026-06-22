// ============================================================
//  PegaFrete — Firebase Cloud Messaging Service Worker
//  ARQUIVO: public/firebase-messaging-sw.js
//
//  Este arquivo PRECISA estar na raiz do domínio (/).
//  O Vite copia tudo de /public para /dist automaticamente.
// ============================================================

// Versão do Firebase usada no SDK compat (deve bater com o package.json)
const FIREBASE_VERSION = '10.13.2';

importScripts(
    `https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-app-compat.js`,
    `https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-messaging-compat.js`
);

// ⚠️  Mesma config do main.js — mantida sincronizada
firebase.initializeApp({
    apiKey: "AIzaSyD7lL5jSj57oLL_wWJWbImUD2Y7TKk3gRI",
    authDomain: "pegafrete-logistica.firebaseapp.com",
    projectId: "pegafrete-logistica",
    storageBucket: "pegafrete-logistica.firebasestorage.app",
    messagingSenderId: "783503103566",
    appId: "1:783503103566:web:840c03b02cda1ba82c151f"
});

const messaging = firebase.messaging();

// ──────────────────────────────────────────────
//  NOTIFICAÇÕES EM BACKGROUND / APP FECHADO
// ──────────────────────────────────────────────
messaging.onBackgroundMessage((payload) => {
    const { title, body, icon, data } = payload.notification || {};
    const click_action = data?.click_action || '/';

    const notificationOptions = {
        body: body || 'Você tem uma nova notificação do PegaFrete.',
        icon: icon || '/orange_truck_avatar.png',
        badge: '/favicon.svg',
        tag: data?.tag || 'pegafrete-notification',
        requireInteraction: false,
        data: { click_action, ...data }
    };

    self.registration.showNotification(
        title || 'PegaFrete',
        notificationOptions
    );
});

// Ao clicar na notificação → abre/foca o app
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const targetUrl = event.notification.data?.click_action || '/';

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clientList) => {
                for (const client of clientList) {
                    if ('focus' in client) return client.focus();
                }
                if (clients.openWindow) return clients.openWindow(targetUrl);
            })
    );
});
