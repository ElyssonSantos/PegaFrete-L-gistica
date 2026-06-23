import firebase from 'firebase/compat/app';
import 'firebase/compat/auth';
import 'firebase/compat/firestore';
import 'firebase/compat/storage';

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

// Inicializa o Firebase
if (!firebase.apps.length) {
    firebase.initializeApp(firebaseConfig);
}

const auth = firebase.auth();
const db = firebase.firestore();
const storage = firebase.storage();
storage.setMaxUploadRetryTime(3000);

export { firebase, auth, db, storage };
