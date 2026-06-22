/**
 * ============================================================
 *  PegaFrete — Envio de Notificações via FCM (Backend / Admin)
 *  ARQUIVO: temp-admin/send-notification.js
 *
 *  Este script roda no SERVIDOR (Node.js), nunca no cliente.
 *  Usa o Firebase Admin SDK para enviar notificações.
 *
 *  USO:
 *    node send-notification.js
 *
 *  INSTALAÇÃO:
 *    npm install firebase-admin
 * ============================================================
 */

const admin = require('firebase-admin');

// Inicializa o Admin SDK com a service account do projeto
// Baixe em: Firebase Console → Project Settings → Service Accounts → Generate new private key
const serviceAccount = require('./serviceAccountKey.json'); // ← coloque o arquivo aqui

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const messaging = admin.messaging();

// ──────────────────────────────────────────────────────────
//  1. ENVIAR PARA UM USUÁRIO ESPECÍFICO (por token)
// ──────────────────────────────────────────────────────────

/**
 * @param {string} token — fcmToken salvo no Firestore
 * @param {object} notification — { title, body }
 * @param {object} data — dados extras opcionais (string keys/values)
 */
async function sendToUser(token, notification, data = {}) {
    if (!token) throw new Error('Token FCM inválido.');

    const message = {
        token,
        notification: {
            title: notification.title || 'PegaFrete',
            body: notification.body || ''
        },
        data: {
            click_action: data.click_action || '/',
            tag: data.tag || 'pegafrete',
            ...Object.fromEntries(
                Object.entries(data).map(([k, v]) => [k, String(v)])
            )
        },
        android: {
            priority: 'high',
            notification: {
                sound: 'default',
                channelId: 'pegafrete_channel'
            }
        },
        webpush: {
            fcmOptions: {
                link: data.click_action || '/'
            }
        }
    };

    try {
        const response = await messaging.send(message);
        console.log('[FCM] Enviado com sucesso:', response);
        return { success: true, response };
    } catch (err) {
        // Token inválido → limpa do Firestore
        if (err.code === 'messaging/registration-token-not-registered') {
            await _clearInvalidToken(token);
        }
        console.error('[FCM] Erro ao enviar:', err.message);
        return { success: false, error: err.message };
    }
}

// ──────────────────────────────────────────────────────────
//  2. ENVIAR PARA TODOS OS USUÁRIOS
// ──────────────────────────────────────────────────────────

async function sendToAll(notification, data = {}) {
    const snapshot = await db.collection('users')
        .where('fcmToken', '!=', null)
        .get();

    const tokens = [];
    snapshot.forEach(doc => {
        const token = doc.data().fcmToken;
        if (token) tokens.push(token);
    });

    return _sendMulticast(tokens, notification, data);
}

// ──────────────────────────────────────────────────────────
//  3. ENVIAR PARA UM GRUPO (por role: 'driver' ou 'shipper')
// ──────────────────────────────────────────────────────────

/**
 * @param {string} role — 'driver' | 'shipper' | 'admin'
 */
async function sendToGroup(role, notification, data = {}) {
    const snapshot = await db.collection('users')
        .where('role', '==', role)
        .where('fcmToken', '!=', null)
        .get();

    const tokens = [];
    snapshot.forEach(doc => {
        const token = doc.data().fcmToken;
        if (token) tokens.push(token);
    });

    console.log(`[FCM] Enviando para ${tokens.length} usuários do grupo "${role}"`);
    return _sendMulticast(tokens, notification, data);
}

// ──────────────────────────────────────────────────────────
//  ENVIO EM LOTE (multicast, máx 500 por chamada)
// ──────────────────────────────────────────────────────────

async function _sendMulticast(tokens, notification, data = {}) {
    if (tokens.length === 0) {
        console.log('[FCM] Nenhum token disponível.');
        return { successCount: 0, failureCount: 0 };
    }

    // FCM aceita no máximo 500 tokens por requisição
    const BATCH_SIZE = 500;
    let totalSuccess = 0;
    let totalFail = 0;

    for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
        const batch = tokens.slice(i, i + BATCH_SIZE);

        const message = {
            notification: {
                title: notification.title || 'PegaFrete',
                body: notification.body || ''
            },
            data: Object.fromEntries(
                Object.entries({ click_action: '/', tag: 'pegafrete', ...data })
                    .map(([k, v]) => [k, String(v)])
            ),
            tokens: batch,
            android: {
                priority: 'high',
                notification: { sound: 'default', channelId: 'pegafrete_channel' }
            }
        };

        const response = await messaging.sendEachForMulticast(message);
        totalSuccess += response.successCount;
        totalFail += response.failureCount;

        // Limpa tokens inválidos
        response.responses.forEach(async (resp, idx) => {
            if (!resp.success) {
                const errorCode = resp.error?.code;
                if (errorCode === 'messaging/registration-token-not-registered') {
                    await _clearInvalidToken(batch[idx]);
                }
            }
        });
    }

    console.log(`[FCM] Lote concluído — Sucesso: ${totalSuccess}, Falha: ${totalFail}`);
    return { successCount: totalSuccess, failureCount: totalFail };
}

// Limpa token inválido do Firestore
async function _clearInvalidToken(token) {
    try {
        const snapshot = await db.collection('users')
            .where('fcmToken', '==', token)
            .limit(1)
            .get();

        snapshot.forEach(doc => {
            doc.ref.update({
                fcmToken: admin.firestore.FieldValue.delete(),
                fcmTokenUpdatedAt: admin.firestore.FieldValue.delete()
            });
        });
    } catch (err) {
        console.error('[FCM] Erro ao limpar token inválido:', err.message);
    }
}

// ──────────────────────────────────────────────────────────
//  EXEMPLOS DE USO
// ──────────────────────────────────────────────────────────

// Descomente e ajuste para testar:

// Enviar para um usuário por token direto:
// sendToUser('TOKEN_FCM_AQUI', { title: 'Nova carga!', body: 'SP → RJ disponível agora.' });

// Enviar para todos os motoristas:
// sendToGroup('driver', { title: 'Novas cargas disponíveis!', body: 'Acesse o app e confira.' });

// Enviar para todos os embarcadores:
// sendToGroup('shipper', { title: 'Motorista encontrado!', body: 'Seu frete foi aceito.' });

// Enviar para TODOS os usuários:
// sendToAll({ title: 'Manutenção programada', body: 'O app estará indisponível das 02h às 04h.' });

module.exports = { sendToUser, sendToAll, sendToGroup };
