// ============================================================
//  PegaFrete — Módulo FCM (Firebase Cloud Messaging)
//  ARQUIVO: src/core/fcm.js
// ============================================================

import { appModular as app, dbModular as db } from './firebaseConfig.js';
import { getMessaging, getToken, onMessage, deleteToken, isSupported } from "firebase/messaging";
import { doc, setDoc, getDoc, deleteDoc, serverTimestamp } from "firebase/firestore";

const VAPID_KEY = 'BOCYZrq8zvdJPRvC95BcavLpVGJpNx4tb3BXLMleQ1O7teHqg_gmTz2GONFrVasf2z1mOekRDrulf7sIZ76Eyr8';

let messaging = null;

export async function initFCM() {
    if (!('serviceWorker' in navigator)) {
        console.warn('[FCM] Service Worker não suportado neste ambiente.');
        return;
    }

    try {
        const supported = await isSupported();
        if (!supported) {
            console.warn('[FCM] Firebase Messaging não é suportado neste navegador/WebView.');
            return;
        }

        messaging = getMessaging(app);
        _listenForegroundMessages();
    } catch (err) {
        console.warn('[FCM] Firebase Messaging não pôde ser inicializado:', err.message);
    }
}

export async function requestNotificationPermission(userId, role = 'driver') {
    if (!messaging) return null;
    if (!('Notification' in window)) return null;
    if (Notification.permission === 'denied') return null;

    try {
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') return null;
        
        return await _generateAndSaveToken(userId, role);
    } catch (err) {
        console.error('[FCM] Erro ao solicitar permissão:', err);
        return null;
    }
}

async function _generateAndSaveToken(userId, role) {
    if (!messaging || !userId) return null;

    try {
        const swReg = await navigator.serviceWorker.register('/firebase-messaging-sw.js', {
            scope: '/'
        });

        try {
            await swReg.update();
        } catch (updateErr) {
            console.warn('[FCM] Falha ao solicitar atualização do Service Worker:', updateErr);
        }

        const token = await getToken(messaging, {
            vapidKey: VAPID_KEY,
            serviceWorkerRegistration: swReg
        });

        if (!token) return null;

        await setDoc(doc(db, 'users', userId), {
            fcmToken: token,
            fcmTokenUpdatedAt: serverTimestamp(),
            fcmPlatform: _detectPlatform(),
            role: role
        }, { merge: true });

        let userName = '';
        let userEmail = '';
        try {
            const uDoc = await getDoc(doc(db, 'users', userId));
            if (uDoc.exists()) {
                userName = uDoc.data().name || '';
                userEmail = uDoc.data().email || '';
            }
        } catch (e) {
            console.error('[FCM] Erro info usuario:', e);
        }

        await setDoc(doc(db, 'fcm_tokens', userId), {
            uid: userId,
            token: token,
            platform: _detectPlatform(),
            updatedAt: serverTimestamp(),
            role: role,
            name: userName,
            email: userEmail
        }, { merge: true });

        localStorage.setItem('pegafrete_fcm_token', token);
        localStorage.setItem('pegafrete_fcm_uid', userId);
        return token;

    } catch (err) {
        console.error('[FCM] Erro ao gerar token:', err);
        return null;
    }
}

function _listenForegroundMessages() {
    if (!messaging) return;
    onMessage(messaging, (payload) => {
        const { title, body, icon } = payload.notification || {};
        const data = payload.data || {};
        if (window.showFCMNotification) {
            window.showFCMNotification({ title, body, icon, data });
        } else if (Notification.permission === 'granted') {
            new Notification(title || 'PegaFrete', {
                body: body || 'Nova notificação.',
                icon: icon || '/pegafrete_logo_new.jpg'
            });
        }
    });
}

function _detectPlatform() {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('android')) return 'android';
    if (ua.includes('iphone') || ua.includes('ipad')) return 'ios';
    if (ua.includes('capacitor')) return 'capacitor';
    return 'web';
}

export async function removeFCMToken(userId) {
    if (!userId) return;
    try {
        const { deleteField } = await import("firebase/firestore");
        await setDoc(doc(db, 'users', userId), {
            fcmToken: deleteField(),
            fcmTokenUpdatedAt: deleteField(),
            fcmPlatform: deleteField()
        }, { merge: true });

        try {
            await deleteDoc(doc(db, 'fcm_tokens', userId));
        } catch (e) {}

        if (messaging) {
            await deleteToken(messaging);
        }

        localStorage.removeItem('pegafrete_fcm_token');
        localStorage.removeItem('pegafrete_fcm_uid');
    } catch (err) {
        console.error('[FCM] Erro ao remover token:', err);
    }
}
