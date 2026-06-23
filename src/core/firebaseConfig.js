import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getStorage } from "firebase/storage";
import { getFirestore, enableMultiTabIndexedDbPersistence } from "firebase/firestore";

// Configuração do Firebase
const firebaseConfig = {
    apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyD7lL5jSj57oLL_wWJWbImUD2Y7TKk3gRI",
    authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "pegafrete-logistica.firebaseapp.com",
    projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "pegafrete-logistica",
    storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "pegafrete-logistica.firebasestorage.app",
    messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "783503103566",
    appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:783503103566:web:840c03b02cda1ba82c151f",
    measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-1HL73CW82D"
};

// Modular (Novo padrão V9+)
export const appModular = initializeApp(firebaseConfig);
export const authModular = getAuth(appModular);
export const dbModular = getFirestore(appModular);
export const storageModular = getStorage(appModular);

// Ativar persistência offline (Múltiplas abas) para evitar que o app pare sem sinal 3G/4G
try {
    enableMultiTabIndexedDbPersistence(dbModular).catch((err) => {
        if (err.code === 'failed-precondition') {
            console.warn('[Firestore] Persistência falhou: Múltiplas abas abertas.');
        } else if (err.code === 'unimplemented') {
            console.warn('[Firestore] Persistência não suportada pelo navegador.');
        }
    });
} catch (e) {
    console.warn('[Firestore] Erro ao ativar persistência offline:', e);
}

// Para não quebrar imports existentes em outros arquivos enquanto ajustamos:
export const firebase = undefined; // Remover dependência final
export const auth = authModular;
export const db = dbModular;
export const storage = storageModular;
