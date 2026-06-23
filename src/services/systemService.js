import { dbModular as db } from '../core/firebaseConfig.js';
import { collection, doc, addDoc, getDoc, onSnapshot, query, where, serverTimestamp, getDocs, writeBatch } from "firebase/firestore";

/**
 * Registra um log de segurança
 */
export async function logSecurityEvent(eventData) {
    try {
        await addDoc(collection(db, "security_logs"), {
            ...eventData,
            timestamp: serverTimestamp()
        });
    } catch (e) {
        console.warn("Erro ao gravar security_log:", e);
    }
}

/**
 * Busca configurações do sistema
 */
export async function getSystemConfig() {
    try {
        const docRef = doc(db, "settings", "system_config");
        const docSnap = await getDoc(docRef);
        if (docSnap.exists()) {
            return docSnap.data();
        }
    } catch (e) {
        console.warn("Erro ao buscar configurações do sistema:", e);
    }
    return null;
}

/**
 * Adiciona uma nova mensagem de sistema
 */
export async function addSystemMessage(messageData) {
    await addDoc(collection(db, "system_messages"), {
        ...messageData,
        createdAt: serverTimestamp()
    });
}

/**
 * Escuta as mensagens de sistema para o usuário
 */
export function subscribeToSystemMessages(uid, callback) {
    const q = query(collection(db, "system_messages"), where("userUid", "==", uid));
    
    return onSnapshot(q, (snapshot) => {
        const messages = [];
        snapshot.forEach(doc => {
            messages.push({ id: doc.id, ...doc.data() });
        });
        callback(messages);
    }, err => {
        console.error("Erro no listener de mensagens do sistema:", err);
    });
}

/**
 * Marca todas as mensagens não lidas do usuário como lidas
 */
export async function markSystemMessagesAsRead(uid) {
    try {
        const q = query(
            collection(db, "system_messages"),
            where("userUid", "==", uid),
            where("read", "==", false)
        );
        const snapshot = await getDocs(q);
        if (snapshot.empty) return;

        const batch = writeBatch(db);
        snapshot.forEach(doc => {
            batch.update(doc.ref, { read: true });
        });
        await batch.commit();
    } catch (err) {
        console.error("Erro ao marcar mensagens como lidas:", err);
    }
}
