import { dbModular as db } from '../core/firebaseConfig.js';
import { doc, getDoc, setDoc, updateDoc, deleteDoc, collection, query, where, getDocs, onSnapshot, serverTimestamp } from "firebase/firestore";

/**
 * Busca o perfil de um usuário pelo UID
 */
export async function getUserProfile(uid) {
    const docRef = doc(db, "users", uid);
    const docSnap = await getDoc(docRef);
    if (docSnap.exists()) {
        return docSnap.data();
    }
    return null;
}

/**
 * Escuta as alterações do perfil do usuário em tempo real
 */
export function subscribeToUserProfile(uid, callback) {
    const docRef = doc(db, "users", uid);
    return onSnapshot(docRef, (docSnap) => {
        if (docSnap.exists()) {
            callback(docSnap.data());
        } else {
            callback(null);
        }
    });
}

/**
 * Atualiza dados parciais do usuário
 */
export async function updateUserProfile(uid, data) {
    const docRef = doc(db, "users", uid);
    await updateDoc(docRef, { ...data, updatedAt: serverTimestamp() });
}

/**
 * Cria ou sobrescreve o perfil de um usuário
 */
export async function setUserProfile(uid, data) {
    const docRef = doc(db, "users", uid);
    await setDoc(docRef, { ...data, updatedAt: serverTimestamp() });
}

/**
 * Verifica se um telefone já está cadastrado em outro usuário
 */
export async function checkPhoneExists(phone) {
    const q = query(collection(db, "users"), where("telefone", "==", phone));
    const querySnapshot = await getDocs(q);
    return !querySnapshot.empty;
}

/**
 * Busca dados de um e-mail registrado na coleção pública
 */
export async function getPublicEmailData(emailKey) {
    const docRef = doc(db, "public_emails", emailKey);
    const docSnap = await getDoc(docRef);
    if (docSnap.exists()) {
        return docSnap.data();
    }
    return null;
}

/**
 * Registra ou atualiza um e-mail na coleção pública
 */
export async function registerPublicEmail(emailKey, provider = 'password') {
    const docRef = doc(db, "public_emails", emailKey);
    await setDoc(docRef, { provider }, { merge: true });
}

/**
 * Remove um e-mail da coleção pública
 */
export async function deletePublicEmail(emailKey) {
    const docRef = doc(db, "public_emails", emailKey);
    await deleteDoc(docRef);
}
