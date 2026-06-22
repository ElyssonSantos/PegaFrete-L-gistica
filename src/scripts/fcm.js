// ============================================================
//  PegaFrete — Módulo FCM (Firebase Cloud Messaging)
//  ARQUIVO: src/scripts/fcm.js
//
//  Responsabilidades:
//  - Registrar o Service Worker de messaging
//  - Solicitar permissão de notificação ao usuário
//  - Gerar/obter o FCM token
//  - Salvar/atualizar o token em Firestore: users/{uid}/fcmToken
//  - Escutar mensagens em foreground
//  - Renovar o token automaticamente quando expirar
// ============================================================

import firebase from 'firebase/compat/app';
import 'firebase/compat/messaging';

// ──────────────────────────────────────────────────────────
// VAPID Key (Web Push Certificate)
// Gere em: Firebase Console → Project Settings → Cloud Messaging
//           → Web Push certificates → Generate Key Pair
// Substitua a string abaixo pela sua VAPID Key real.
// ──────────────────────────────────────────────────────────
const VAPID_KEY = 'BEl62iUYgUivxIkv69yViEuiBIa40HI80NM9DGbM_YW_M'; // ← SUBSTITUA

let messaging = null;
let _db = null;

/**
 * Inicializa o módulo FCM.
 * Deve ser chamado após o Firebase estar inicializado.
 * @param {firebase.firestore.Firestore} db  — instância do Firestore
 */
export function initFCM(db) {
    _db = db;

    // FCM não funciona em ambientes sem SW (ex: http puro sem SSL)
    if (!('serviceWorker' in navigator)) {
        console.warn('[FCM] Service Worker não suportado neste ambiente.');
        return;
    }

    try {
        messaging = firebase.messaging();
        _listenForegroundMessages();
        _setupTokenRefresh();
    } catch (err) {
        console.warn('[FCM] Firebase Messaging não pôde ser inicializado:', err.message);
    }
}

// ──────────────────────────────────────────────────────────
//  PEDIR PERMISSÃO + REGISTRAR TOKEN
//  Chamar após o usuário fazer login (passa o uid)
// ──────────────────────────────────────────────────────────

/**
 * Solicita permissão de notificação ao usuário e,
 * se concedida, gera o FCM token e salva no Firestore.
 *
 * @param {string} userId — auth.currentUser.uid
 * @param {string} role   — 'driver' | 'shipper' | 'admin'
 */
export async function requestNotificationPermission(userId, role = 'driver') {
    if (!messaging) {
        console.warn('[FCM] Messaging não inicializado.');
        return null;
    }

    // Verifica se o browser suporta Notification API
    if (!('Notification' in window)) {
        console.warn('[FCM] Este browser não suporta notificações.');
        return null;
    }

    // Já foi bloqueado → não pergunta de novo (não adianta)
    if (Notification.permission === 'denied') {
        console.warn('[FCM] Permissão de notificação negada pelo usuário.');
        return null;
    }

    try {
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
            console.warn('[FCM] Permissão não concedida.');
            return null;
        }

        const token = await _generateAndSaveToken(userId, role);
        return token;

    } catch (err) {
        console.error('[FCM] Erro ao solicitar permissão:', err);
        return null;
    }
}

// ──────────────────────────────────────────────────────────
//  GERAR TOKEN E SALVAR NO FIRESTORE
// ──────────────────────────────────────────────────────────

async function _generateAndSaveToken(userId, role) {
    if (!messaging || !_db || !userId) return null;

    try {
        // Registra o SW de messaging se ainda não foi registrado
        const swReg = await navigator.serviceWorker.register('/firebase-messaging-sw.js', {
            scope: '/'
        });

        // Obtém o token FCM
        const token = await messaging.getToken({
            vapidKey: VAPID_KEY,
            serviceWorkerRegistration: swReg
        });

        if (!token) {
            console.warn('[FCM] Token não gerado. Verifique a VAPID Key.');
            return null;
        }

        // Salva no Firestore: users/{uid} com merge para não sobrescrever outros dados
        await _db.collection('users').doc(userId).set({
            fcmToken: token,
            fcmTokenUpdatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            fcmPlatform: _detectPlatform(),
            role: role
        }, { merge: true });

        console.log('[FCM] Token salvo com sucesso.');

        // Armazena localmente para comparação futura (detecção de renovação)
        localStorage.setItem('pegafrete_fcm_token', token);
        localStorage.setItem('pegafrete_fcm_uid', userId);

        return token;

    } catch (err) {
        console.error('[FCM] Erro ao gerar token:', err);
        return null;
    }
}

// ──────────────────────────────────────────────────────────
//  RENOVAÇÃO AUTOMÁTICA DE TOKEN
//  O Firebase renova o token quando o app é reinstalado
//  ou o token expira. Detectamos isso e atualizamos.
// ──────────────────────────────────────────────────────────

function _setupTokenRefresh() {
    if (!messaging) return;

    // onTokenRefresh é chamado pelo SDK quando o token muda
    messaging.onTokenRefresh(async () => {
        const uid = localStorage.getItem('pegafrete_fcm_uid');
        const savedToken = localStorage.getItem('pegafrete_fcm_token');

        if (!uid) return;

        try {
            const swReg = await navigator.serviceWorker.ready;
            const newToken = await messaging.getToken({
                vapidKey: VAPID_KEY,
                serviceWorkerRegistration: swReg
            });

            if (newToken && newToken !== savedToken) {
                const userRef = _db.collection('users').doc(uid);
                const userDoc = await userRef.get();
                const role = userDoc.exists ? userDoc.data().role : 'driver';

                await _generateAndSaveToken(uid, role);
                console.log('[FCM] Token renovado e atualizado no Firestore.');
            }
        } catch (err) {
            console.error('[FCM] Erro ao renovar token:', err);
        }
    });
}

// ──────────────────────────────────────────────────────────
//  NOTIFICAÇÕES EM FOREGROUND (app aberto)
// ──────────────────────────────────────────────────────────

function _listenForegroundMessages() {
    if (!messaging) return;

    messaging.onMessage((payload) => {
        const { title, body, icon } = payload.notification || {};
        const data = payload.data || {};

        console.log('[FCM] Mensagem recebida em foreground:', payload);

        // Exibe notificação visual no app (usando a função showToast do main.js)
        if (window.showFCMNotification) {
            window.showFCMNotification({ title, body, icon, data });
        } else {
            // Fallback: usa a Notification API nativa se o toast não estiver disponível
            if (Notification.permission === 'granted') {
                new Notification(title || 'PegaFrete', {
                    body: body || 'Nova notificação.',
                    icon: icon || '/orange_truck_avatar.png'
                });
            }
        }
    });
}

// ──────────────────────────────────────────────────────────
//  UTILITÁRIOS
// ──────────────────────────────────────────────────────────

function _detectPlatform() {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('android')) return 'android';
    if (ua.includes('iphone') || ua.includes('ipad')) return 'ios';
    if (ua.includes('capacitor')) return 'capacitor';
    return 'web';
}

/**
 * Remove o FCM token do Firestore quando o usuário faz logout.
 * Evita receber notificações após sair da conta.
 * @param {string} userId
 */
export async function removeFCMToken(userId) {
    if (!_db || !userId) return;
    try {
        await _db.collection('users').doc(userId).set({
            fcmToken: firebase.firestore.FieldValue.delete(),
            fcmTokenUpdatedAt: firebase.firestore.FieldValue.delete(),
            fcmPlatform: firebase.firestore.FieldValue.delete()
        }, { merge: true });

        if (messaging) {
            await messaging.deleteToken();
        }

        localStorage.removeItem('pegafrete_fcm_token');
        localStorage.removeItem('pegafrete_fcm_uid');
        console.log('[FCM] Token removido após logout.');
    } catch (err) {
        console.error('[FCM] Erro ao remover token:', err);
    }
}
