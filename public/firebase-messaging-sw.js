// ============================================================
//  PegaFrete — Firebase Cloud Messaging Service Worker
//  ARQUIVO: public/firebase-messaging-sw.js
//
//  Este arquivo PRECISA estar na raiz do domínio (/).
//  O Vite copia tudo de /public para /dist automaticamente.
// ============================================================

import { precacheAndRoute } from 'workbox-precaching';
import { initializeApp } from 'firebase/app';
import { getMessaging, onBackgroundMessage } from 'firebase/messaging/sw';

// Precache resources for offline mode (VitePWA injectManifest)
precacheAndRoute(self.__WB_MANIFEST || []);

// ⚠️ Mesma config do main.js — mantida sincronizada
const firebaseConfig = {
    apiKey: "AIzaSyD7lL5jSj57oLL_wWJWbImUD2Y7TKk3gRI",
    authDomain: "pegafrete-logistica.firebaseapp.com",
    projectId: "pegafrete-logistica",
    storageBucket: "pegafrete-logistica.firebasestorage.app",
    messagingSenderId: "783503103566",
    appId: "1:783503103566:web:840c03b02cda1ba82c151f"
};

const app = initializeApp(firebaseConfig);
const messaging = getMessaging(app);

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
onBackgroundMessage(messaging, (payload) => {
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
    const icon = data.icon || '/pegafrete_logo_new.jpg';
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
