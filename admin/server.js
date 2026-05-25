const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
//  1. FIREBASE ADMIN SDK — INICIALIZAÇÃO SEGURA
// ============================================================
try {
    let credential = null;
    const saJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

    if (saJson) {
        try {
            // Tenta parsear como JSON string direto
            credential = admin.credential.cert(JSON.parse(saJson));
        } catch (_) {
            // Se falhou, tenta como caminho de arquivo
            const fs = require('fs');
            const resolved = path.resolve(saJson);
            if (fs.existsSync(resolved)) {
                credential = admin.credential.cert(
                    JSON.parse(fs.readFileSync(resolved, 'utf8'))
                );
            }
        }
    }

    admin.initializeApp(credential ? { credential } : undefined);
    console.log('[Firebase Admin] SDK inicializado com sucesso.');
} catch (err) {
    console.error('[Firebase Admin] FALHA NA INICIALIZAÇÃO:', err.message);
    console.warn('[Firebase Admin] Servidor rodando sem conexão ao Firebase. Rotas de API retornarão 503.');
}

const db = admin.apps.length ? admin.firestore() : null;
const authAdmin = admin.apps.length ? admin.auth() : null;

// ============================================================
//  2. MIDDLEWARES DE SEGURANÇA
// ============================================================

// Helmet — Headers de segurança (CSP, HSTS, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://www.gstatic.com", "https://unpkg.com", "https://apis.google.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://unpkg.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: [
                "'self'",
                "https://*.googleapis.com",
                "https://*.firebaseio.com",
                "wss://*.firebaseio.com",
                "https://identitytoolkit.googleapis.com",
                "https://securetoken.googleapis.com"
            ],
            frameSrc: ["'self'", "https://*.firebaseapp.com", "https://accounts.google.com"]
        }
    }
}));

// CORS — Whitelist de origens autorizadas
const ALLOWED_ORIGINS = [
    'http://localhost:5000',
    'http://localhost:3000',
    'http://127.0.0.1:5000'
    // Adicione aqui o domínio de produção: 'https://admin.pegafrete.com.br'
];
app.use(cors({
    origin(origin, cb) {
        // Permite requisições sem origin (Postman, curl, server-to-server)
        if (!origin) return cb(null, true);
        if (ALLOWED_ORIGINS.includes(origin) || process.env.NODE_ENV !== 'production') {
            return cb(null, true);
        }
        cb(new Error('Origem bloqueada pela política de CORS'));
    },
    credentials: true
}));

// Body parser
app.use(express.json({ limit: '1mb' }));

// Rate Limiting — 100 req / 15 min por IP em rotas de API
app.use('/api/', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Limite de requisições atingido. Aguarde 15 minutos.' }
}));

// Servir frontend estático
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
//  3. MIDDLEWARE DE AUTENTICAÇÃO — JWT + CUSTOM CLAIMS
// ============================================================
async function verifyAdminToken(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token de autenticação ausente.' });
    }

    if (!authAdmin) {
        return res.status(503).json({ error: 'Firebase Admin SDK indisponível.' });
    }

    try {
        const token = header.split('Bearer ')[1];
        const decoded = await authAdmin.verifyIdToken(token);

        if (decoded.admin !== true) {
            console.warn(`[SEGURANÇA] Acesso admin negado para UID: ${decoded.uid}`);
            return res.status(403).json({ error: 'Privilégios de Administrador requeridos.' });
        }

        req.user = decoded;
        next();
    } catch (err) {
        const msg = err.code === 'auth/id-token-expired'
            ? 'Token expirado. Faça login novamente.'
            : 'Token inválido.';
        return res.status(401).json({ error: msg });
    }
}

// Helper: garante que Firestore está disponível
function requireDb(res) {
    if (!db) {
        res.status(503).json({ error: 'Banco de dados indisponível.' });
        return false;
    }
    return true;
}

// ============================================================
//  4. ROTAS DA API
// ============================================================

// ---- SETUP: Promoção do primeiro admin ----
app.post('/api/admin/setup-claims', async (req, res) => {
    const { uid, secret } = req.body;
    if (!uid || !secret) {
        return res.status(400).json({ error: 'Informe uid e secret.' });
    }
    if (secret !== (process.env.ADMIN_SETUP_SECRET || '')) {
        return res.status(403).json({ error: 'Chave secreta incorreta.' });
    }
    if (!authAdmin || !requireDb(res)) return;

    try {
        await authAdmin.setCustomUserClaims(uid, { admin: true });
        await db.collection('users').doc(uid).set(
            { role: 'admin', updatedAt: admin.firestore.FieldValue.serverTimestamp() },
            { merge: true }
        );
        console.log(`[SETUP] UID ${uid} promovido a Administrador.`);
        res.json({ success: true, message: 'Usuário promovido a admin. Faça logout e login novamente para ativar.' });
    } catch (err) {
        console.error('[SETUP] Erro:', err.message);
        res.status(500).json({ error: 'Falha ao definir claims: ' + err.message });
    }
});

// ---- STATS: Métricas operacionais ----
app.get('/api/admin/stats', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [usersSnap, freightsSnap, logsSnap] = await Promise.all([
            db.collection('users').get(),
            db.collection('freights').get(),
            db.collection('security_logs').get()
        ]);

        let shippers = 0, drivers = 0, pending = 0;
        usersSnap.forEach(doc => {
            const d = doc.data();
            if (d.role === 'shipper') shippers++;
            else if (d.role === 'driver') drivers++;
            if (d.documentStatus === 'pending') pending++;
        });

        res.json({
            totalShippers: shippers,
            totalDrivers: drivers,
            pendingDocuments: pending,
            totalFreights: freightsSnap.size,
            securityLogs: logsSnap.size,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[STATS]', err.message);
        res.status(500).json({ error: 'Falha ao buscar estatísticas.' });
    }
});

// ---- USERS: Listar usuários ----
app.get('/api/admin/users', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const role = req.query.role; // ?role=driver ou ?role=shipper
        let query = db.collection('users');
        if (role && ['driver', 'shipper', 'admin'].includes(role)) {
            query = query.where('role', '==', role);
        }
        const snap = await query.get();
        const users = [];
        snap.forEach(doc => users.push({ uid: doc.id, ...doc.data() }));
        res.json(users);
    } catch (err) {
        console.error('[USERS]', err.message);
        res.status(500).json({ error: 'Falha ao listar usuários.' });
    }
});

// ---- USERS: Detalhes de um usuário ----
app.get('/api/admin/users/:uid', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const doc = await db.collection('users').doc(req.params.uid).get();
        if (!doc.exists) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.json({ uid: doc.id, ...doc.data() });
    } catch (err) {
        console.error('[USER DETAIL]', err.message);
        res.status(500).json({ error: 'Falha ao buscar usuário.' });
    }
});

// ---- USERS: Atualizar dados de um usuário ----
app.put('/api/admin/users/:uid', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    const { uid } = req.params;
    // Campos que o admin pode alterar
    const allowed = ['name', 'email', 'phone', 'address', 'role', 'vehicle', 'documentStatus', 'rating'];
    const update = {};
    for (const key of allowed) {
        if (req.body[key] !== undefined) update[key] = req.body[key];
    }
    if (Object.keys(update).length === 0) {
        return res.status(400).json({ error: 'Nenhum campo válido para atualização.' });
    }
    update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    update.updatedByAdmin = req.user.uid;

    try {
        const userDoc = await db.collection('users').doc(uid).get();
        if (!userDoc.exists) return res.status(404).json({ error: 'Usuário não encontrado.' });

        await db.collection('users').doc(uid).update(update);
        res.json({ success: true, message: 'Usuário atualizado.' });
    } catch (err) {
        console.error('[USER UPDATE]', err.message);
        res.status(500).json({ error: 'Falha ao atualizar usuário.' });
    }
});

// ---- FREIGHTS: Listar fretes ----
app.get('/api/admin/freights', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 200);
        const snap = await db.collection('freights')
            .orderBy('createdAt', 'desc')
            .limit(limit)
            .get();
        const freights = [];
        snap.forEach(doc => freights.push({ id: doc.id, ...doc.data() }));
        res.json(freights);
    } catch (err) {
        console.error('[FREIGHTS]', err.message);
        res.status(500).json({ error: 'Falha ao listar fretes.' });
    }
});

// ---- FREIGHTS: Atualizar status de um frete ----
app.put('/api/admin/freights/:id', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    const { id } = req.params;
    const allowed = ['status', 'status_pagamento', 'pagamento_liberado', 'obs'];
    const update = {};
    for (const key of allowed) {
        if (req.body[key] !== undefined) update[key] = req.body[key];
    }
    if (Object.keys(update).length === 0) {
        return res.status(400).json({ error: 'Nenhum campo válido para atualização.' });
    }
    update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    update.updatedByAdmin = req.user.uid;

    try {
        const freightDoc = await db.collection('freights').doc(id).get();
        if (!freightDoc.exists) return res.status(404).json({ error: 'Frete não encontrado.' });

        await db.collection('freights').doc(id).update(update);

        // Log de auditoria
        await db.collection('security_logs').add({
            uid: req.user.uid,
            event: 'FREIGHT_UPDATE_ADMIN',
            details: `Admin atualizou frete ${id}: ${JSON.stringify(update)}`,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            page: '/admin/freights'
        });

        res.json({ success: true, message: 'Frete atualizado.' });
    } catch (err) {
        console.error('[FREIGHT UPDATE]', err.message);
        res.status(500).json({ error: 'Falha ao atualizar frete.' });
    }
});

// ---- DOCUMENTS: Listar pendentes ----
app.get('/api/admin/documents/pending', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const snap = await db.collection('users')
            .where('documentStatus', '==', 'pending')
            .get();
        const list = [];
        snap.forEach(doc => list.push({ uid: doc.id, ...doc.data() }));

        // Fallback: se ninguém tem documentStatus, pega quem tem documentsUploaded
        if (list.length === 0) {
            const fallback = await db.collection('users').get();
            fallback.forEach(doc => {
                const d = doc.data();
                if (d.documentsUploaded && d.documentStatus !== 'verified') {
                    list.push({ uid: doc.id, ...d });
                }
            });
        }

        res.json(list);
    } catch (err) {
        console.error('[DOCS PENDING]', err.message);
        res.status(500).json({ error: 'Falha ao buscar documentos pendentes.' });
    }
});

// ---- DOCUMENTS: Aprovar / Rejeitar ----
app.post('/api/admin/documents/verify', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    const { uid, status, reason } = req.body;
    if (!uid || !['verified', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Informe uid e status (verified ou rejected).' });
    }
    if (status === 'rejected' && !reason) {
        return res.status(400).json({ error: 'Justificativa obrigatória para rejeição.' });
    }

    try {
        const userDoc = await db.collection('users').doc(uid).get();
        if (!userDoc.exists) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const batch = db.batch();

        // 1. Atualizar perfil do usuário
        const userRef = db.collection('users').doc(uid);
        const userUpdate = {
            documentStatus: status,
            documentVerifiedAt: admin.firestore.FieldValue.serverTimestamp(),
            documentVerifierUid: req.user.uid
        };
        if (status === 'rejected') userUpdate.documentRejectionReason = reason;
        batch.update(userRef, userUpdate);

        // 2. Notificar o usuário via system_messages
        const msgRef = db.collection('system_messages').doc();
        batch.set(msgRef, {
            userUid: uid,
            title: status === 'verified' ? '✅ Documentos Aprovados!' : '❌ Documentos Rejeitados',
            message: status === 'verified'
                ? 'Seus documentos foram validados com sucesso. Sua conta está totalmente liberada!'
                : `Seus documentos não foram aprovados. Motivo: ${reason}`,
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            type: status === 'verified' ? 'success' : 'error'
        });

        // 3. Log de auditoria
        const logRef = db.collection('security_logs').doc();
        batch.set(logRef, {
            uid: req.user.uid,
            event: 'DOCUMENT_VERIFICATION',
            details: `Admin ${req.user.email || req.user.uid} ${status === 'verified' ? 'APROVOU' : 'REJEITOU'} docs de ${uid}. ${reason || ''}`,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            page: '/admin/documents'
        });

        await batch.commit();
        res.json({ success: true, message: `Documento ${status === 'verified' ? 'aprovado' : 'rejeitado'} com sucesso. Usuário notificado.` });
    } catch (err) {
        console.error('[DOC VERIFY]', err.message);
        res.status(500).json({ error: 'Falha ao processar verificação.' });
    }
});

// ---- NOTIFICATIONS: Enviar mensagem ----
app.post('/api/admin/notifications/send', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    const { targetUid, title, message } = req.body;
    if (!targetUid || !title || !message) {
        return res.status(400).json({ error: 'Campos obrigatórios: targetUid, title, message.' });
    }

    try {
        const batch = db.batch();
        let count = 0;

        if (targetUid === 'all') {
            const usersSnap = await db.collection('users').get();
            usersSnap.forEach(doc => {
                const msgRef = db.collection('system_messages').doc();
                batch.set(msgRef, {
                    userUid: doc.id,
                    title, message,
                    read: false,
                    createdAt: admin.firestore.FieldValue.serverTimestamp(),
                    type: 'admin_broadcast'
                });
                count++;
            });
        } else {
            const userDoc = await db.collection('users').doc(targetUid).get();
            if (!userDoc.exists) {
                return res.status(404).json({ error: 'Usuário destinatário não encontrado.' });
            }
            const msgRef = db.collection('system_messages').doc();
            batch.set(msgRef, {
                userUid: targetUid,
                title, message,
                read: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                type: 'admin_alert'
            });
            count = 1;
        }

        // Log de auditoria
        const logRef = db.collection('security_logs').doc();
        batch.set(logRef, {
            uid: req.user.uid,
            event: 'ADMIN_NOTIFICATION_SEND',
            details: `Admin enviou "${title}" para ${targetUid === 'all' ? `todos (${count} usuários)` : targetUid}`,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            page: '/admin/notifications'
        });

        await batch.commit();
        res.json({ success: true, message: `Notificação enviada para ${count} usuário(s).` });
    } catch (err) {
        console.error('[NOTIFICATION]', err.message);
        res.status(500).json({ error: 'Falha ao enviar notificação.' });
    }
});

// ---- LOGS: Auditoria ----
app.get('/api/admin/logs', verifyAdminToken, async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const snap = await db.collection('security_logs')
            .orderBy('timestamp', 'desc')
            .limit(100)
            .get();
        const logs = [];
        snap.forEach(doc => logs.push({ id: doc.id, ...doc.data() }));
        res.json(logs);
    } catch (err) {
        console.error('[LOGS]', err.message);
        res.status(500).json({ error: 'Falha ao recuperar logs.' });
    }
});

// ============================================================
//  5. ROTAS DE FRONTEND (catch-all)
// ============================================================
app.get('/dashboard', (_, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('*', (req, res) => {
    // Não intercepta chamadas à API
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Rota não encontrada.' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
//  6. INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () => {
    console.log('═══════════════════════════════════════════════');
    console.log(` PEGAFRETE ADMIN API — Porta ${PORT}`);
    console.log(` http://localhost:${PORT}`);
    console.log(` Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log(` Firebase: ${admin.apps.length ? 'Conectado' : 'Desconectado'}`);
    console.log('═══════════════════════════════════════════════');
});
