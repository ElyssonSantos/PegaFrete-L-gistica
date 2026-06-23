import { authModular as auth, dbModular as db } from './firebaseConfig.js';
import { signInWithEmailAndPassword, signInWithPopup, GoogleAuthProvider, sendPasswordResetEmail, signOut, deleteUser, RecaptchaVerifier, signInWithPhoneNumber } from "firebase/auth";
import { doc, getDoc, deleteDoc } from "firebase/firestore";

export async function loginWithEmail(email, password) {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const docRef = doc(db, "users", userCredential.user.uid);
    const docSnap = await getDoc(docRef);
    if (docSnap.exists()) {
        return { user: userCredential.user, data: docSnap.data() };
    } else {
        throw { code: 'custom/user-not-found', message: 'Perfil de usuário não encontrado.' };
    }
}

export async function loginWithGooglePopup() {
    const provider = new GoogleAuthProvider();
    return await signInWithPopup(auth, provider);
}

export async function sendPasswordReset(email) {
    return await sendPasswordResetEmail(auth, email);
}

export async function signOutUser() {
    return await signOut(auth);
}

export async function deleteUserAccount() {
    const user = auth.currentUser;
    if (!user) throw new Error("Usuário não autenticado");
    
    // Attempt to delete user doc in Firestore
    const docRef = doc(db, "users", user.uid);
    await deleteDoc(docRef);
    
    // Delete auth user
    await deleteUser(user);
}

export async function sendSMSVerification(phoneNumber, containerId) {
    if (!window.recaptchaVerifier) {
        window.recaptchaVerifier = new RecaptchaVerifier(auth, containerId, {
            'size': 'invisible'
        });
    }
    return await signInWithPhoneNumber(auth, phoneNumber, window.recaptchaVerifier);
}
