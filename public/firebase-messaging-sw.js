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

// Força a ativação imediata do novo Service Worker assim que instalado
self.addEventListener('install', (event) => {
    self.skipWaiting();
});

// Assume o controle dos clientes imediatamente
self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

// ──────────────────────────────────────────────
//  NOTIFICAÇÕES EM BACKGROUND / APP FECHADO
// ──────────────────────────────────────────────
messaging.onBackgroundMessage((payload) => {
    console.log('[FCM SW] Mensagem em background recebida:', payload);

    // Se o payload contiver 'notification', o navegador/SO já exibe a notificação automaticamente.
    // Retornamos cedo para evitar que o service worker chame showNotification e duplique no Android/Chrome.
    if (payload.notification) {
        console.log('[FCM SW] Notificação tratada nativamente pelo navegador.');
        return;
    }

    // Se for uma notificação de dados pura (data-only), exibimos manualmente:
    const data = payload.data || {};
    const title = data.title || 'PegaFrete';
    const body = data.body || 'Você tem uma nova notificação.';
    const icon = data.icon || '/orange_truck_avatar.png';
    const click_action = data.click_action || '/';

    const notificationOptions = {
        body: body,
        icon: icon,
        badge: '/favicon.svg',
        tag: data.tag || 'pegafrete-notification',
        requireInteraction: false,
        data: { click_action, ...data }
    };

    self.registration.showNotification(title, notificationOptions);
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
