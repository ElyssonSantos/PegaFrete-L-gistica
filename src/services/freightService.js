import { dbModular as db } from '../core/firebaseConfig.js';
import { collection, doc, addDoc, updateDoc, onSnapshot, query, orderBy, limit, serverTimestamp } from "firebase/firestore";

/**
 * Escuta os fretes mais recentes em tempo real
 * @param {function} callback - Função chamada sempre que os dados mudam
 * @returns {function} Unsubscribe function
 */
export function subscribeToFreights(callback) {
    const q = query(collection(db, "freights"), orderBy("createdAt", "desc"), limit(20));
    
    const unsubscribe = onSnapshot(q, (snapshot) => {
        const freightsList = [];
        snapshot.forEach((doc) => {
            freightsList.push({ id: doc.id, ...doc.data() });
        });
        callback(freightsList);
    }, (error) => {
        console.error("Erro ao escutar fretes:", error);
    });

    return unsubscribe;
}

/**
 * Adiciona um novo frete
 * @param {object} freightData - Dados do frete
 * @returns {Promise<string>} ID do frete adicionado
 */
export async function addFreight(freightData) {
    const docRef = await addDoc(collection(db, "freights"), {
        ...freightData,
        createdAt: serverTimestamp()
    });
    return docRef.id;
}

/**
 * Atualiza um frete existente
 * @param {string} freightId - ID do frete
 * @param {object} updatedData - Dados a serem atualizados
 */
export async function updateFreight(freightId, updatedData) {
    const docRef = doc(db, "freights", freightId);
    await updateDoc(docRef, {
        ...updatedData,
        updatedAt: serverTimestamp()
    });
}

/**
 * Atualiza apenas o status de um frete
 * @param {string} freightId - ID do frete
 * @param {string} status - Novo status ("entregue", "cancelado", etc.)
 */
export async function updateFreightStatus(freightId, status) {
    const docRef = doc(db, "freights", freightId);
    await updateDoc(docRef, { status, updatedAt: serverTimestamp() });
}

/**
 * Aceita uma carga (motorista)
 * @param {string} freightId - ID do frete
 * @param {string} driverUid - UID do motorista
 */
export async function acceptFreight(freightId, driverUid) {
    const docRef = doc(db, "freights", freightId);
    await updateDoc(docRef, {
        status: 'transito',
        driverUid: driverUid,
        acceptedAt: serverTimestamp()
    });
}
