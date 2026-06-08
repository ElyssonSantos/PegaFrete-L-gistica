import firebase from 'firebase/compat/app';
import 'firebase/compat/auth';
import 'firebase/compat/firestore';
import 'firebase/compat/storage';

// ====== ZERO TRUST HARDENING ======
// PrevenÃ§Ã£o de vazamento de dados em ProduÃ§Ã£o
if (import.meta.env?.PROD || window.location.hostname !== 'localhost') {
    // Sobrescreve mÃ©todos de console para evitar vazamento de tokens e logs na rede
    console.log = function() {};
    console.warn = function() {};
    console.info = function() {};
    console.debug = function() {};
    // MantÃ©m apenas console.error genÃ©rico (opcional, ou pode desativar tambÃ©m)
    const originalError = console.error;
    console.error = function() {
        originalError("[Security] Application Error");
    };
    
    // Desativa DevTools Debugger
    setInterval(() => {
        const devtools = /./;
        devtools.toString = function() {
            debugger;
        }
    }, 1000);
}

// ProteÃ§Ã£o contra Brute Force / Rate Limiting Local
let loginAttempts = 0;
let lastLoginAttemptTime = 0;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_COOLDOWN_MS = 60000; // 1 minuto
// ConfiguraÃ§Ã£o do Firebase
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

// ==========================================
// PROTEÃ‡ÃƒO DE FRONTEND E ANTI-DEVTOOLS
// ==========================================

// Bloqueia clique com botÃ£o direito
document.addEventListener('contextmenu', event => event.preventDefault());

// Bloqueia atalhos comuns de inspeÃ§Ã£o
document.addEventListener('keydown', event => {
    // F12
    if (event.keyCode === 123) {
        event.preventDefault();
        return false;
    }
    // Ctrl+Shift+I ou Cmd+Option+I (Inspecionar)
    if (event.ctrlKey && event.shiftKey && event.keyCode === 73) {
        event.preventDefault();
        return false;
    }
    // Ctrl+Shift+J ou Cmd+Option+J (Console)
    if (event.ctrlKey && event.shiftKey && event.keyCode === 74) {
        event.preventDefault();
        return false;
    }
    // Ctrl+U ou Cmd+U (Ver CÃ³digo Fonte)
    if (event.ctrlKey && event.keyCode === 85) {
        event.preventDefault();
        return false;
    }
    // Ctrl+S ou Cmd+S (Salvar pÃ¡gina)
    if (event.ctrlKey && event.keyCode === 83) {
        event.preventDefault();
        return false;
    }
});


const auth = firebase.auth();
const db = firebase.firestore();
const storage = firebase.storage();
storage.setMaxUploadRetryTime(3000);



let navHistory = ['splash'];
window.history.replaceState({ screen: 'splash' }, "", "#splash");
let currentUserRole = null;
let userData = {};
let tempPhone = '';
let tempRole = '';
let isRegisteringProcess = false; // Flag to block onAuthStateChanged auto-redirects during registration
let smsSendCooldown = false; // Rate limit para envio de SMS

// ====== SEGURANÃ‡A: SANITIZAÃ‡ÃƒO E VALIDAÃ‡ÃƒO ======

/**
 * Client-side input sanitization (Defense in Depth)
 * Firestore Security Rules fornecem a proteÃ§Ã£o primÃ¡ria.
 * Esta camada adicional impede injeÃ§Ã£o de HTML/JS antes de gravar.
 */
function sanitizeInput(str, maxLen = 500) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .trim()
        .slice(0, maxLen);
}

// ====== SEGURANÃ‡A: LOGS E MONITORAMENTO ======
async function logSecurityEvent(event, details) {
    try {
        const user = auth.currentUser;
        const uid = user ? user.uid : 'unauthenticated';

        // Em produÃ§Ã£o, isso gravaria no Firestore (coleÃ§Ã£o security_logs)
        // Apenas o backend ou o prÃ³prio usuÃ¡rio pode ler seus logs.
        if (user) {
            await db.collection('security_logs').add({
                uid: uid,
                event: event,
                details: details,
                timestamp: firebase.firestore.FieldValue.serverTimestamp(),
                page: window.location.pathname
            });
        }
        console.warn(`[SECURITY LOG] ${event}:`, details);
    } catch (err) {
        console.error('Falha ao gravar log de seguranÃ§a', err);
    }
}

// ====== SEGURANÃ‡A: VALIDAÃ‡ÃƒO DE ARQUIVOS (MAGIC BYTES) ======
async function validateFile(file, isProfilePhoto = false) {
    if (!file) return { valid: false, error: 'Nenhum arquivo selecionado.' };

    // 1. Validar tamanho
    const maxSize = isProfilePhoto ? 10 * 1024 * 1024 : 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
        return { valid: false, error: `Arquivo muito grande. O limite Ã© ${maxSize / (1024 * 1024)}MB.` };
    }

    // 2. Validar MIME Type bÃ¡sico
    const allowedTypes = isProfilePhoto
        ? ['image/jpeg', 'image/png', 'image/webp']
        : ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];

    if (!allowedTypes.includes(file.type)) {
        return { valid: false, error: 'Formato de arquivo nÃ£o permitido. Use JPG, PNG, WEBP ou PDF.' };
    }

    // 3. Validar nome do arquivo (Path traversal e XSS extensions)
    if (file.name.includes('..') || /\.(exe|sh|bat|cmd|js|vbs|php|phtml|html|htm|svg)$/i.test(file.name)) {
        logSecurityEvent('SUSPICIOUS_FILE_NAME', `Tentativa de upload de arquivo com nome perigoso: ${file.name}`);
        return { valid: false, error: 'Nome ou tipo de arquivo suspeito e foi bloqueado por seguranÃ§a.' };
    }

    // 4. VerificaÃ§Ã£o de Magic Bytes (Assinatura Hexadecimal) - Zero Trust Upload
    try {
        const magic = await readMagicBytes(file);
        let isValidMagic = false;
        
        // Assinaturas Hexadecimais Conhecidas
        if (magic.startsWith('ffd8ffe0') || magic.startsWith('ffd8ffe1') || magic.startsWith('ffd8ffe2')) isValidMagic = true; // JPEG/JPG
        if (magic.startsWith('89504e47')) isValidMagic = true; // PNG
        if (magic.startsWith('52494646') && magic.substring(16, 24) === '57454250') isValidMagic = true; // WEBP
        if (!isProfilePhoto && magic.startsWith('25504446')) isValidMagic = true; // PDF
        
        if (!isValidMagic) {
            logSecurityEvent('MAGIC_BYTES_MISMATCH', `MIME falsificado detectado. Arquivo: ${file.name}, Assinatura: ${magic}`);
            return { valid: false, error: 'Assinatura de arquivo invÃ¡lida. PossÃ­vel falsificaÃ§Ã£o de formato detectada.' };
        }
    } catch (err) {
        console.error("Erro na leitura de magic bytes:", err);
        return { valid: false, error: 'Falha na validaÃ§Ã£o de integridade do arquivo.' };
    }

    return { valid: true };
}

// FunÃ§Ã£o auxiliar para extrair os primeiros 4 bytes do arquivo (Hex)
function readMagicBytes(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = function(e) {
            if (e.target.readyState === FileReader.DONE) {
                const arr = (new Uint8Array(e.target.result)).subarray(0, 4);
                let hex = '';
                for (let i = 0; i < arr.length; i++) {
                    hex += arr[i].toString(16).padStart(2, '0');
                }
                // Adicionalmente para WEBP, precisamos ler atÃ© o byte 12 (4+4+4)
                if (hex === '52494646' && file.size > 12) {
                    const reader2 = new FileReader();
                    reader2.onloadend = function(e2) {
                        const arr2 = new Uint8Array(e2.target.result);
                        let hex2 = hex;
                        for(let j = 4; j < 12; j++) hex2 += arr2[j].toString(16).padStart(2, '0');
                        resolve(hex2);
                    };
                    reader2.readAsArrayBuffer(file.slice(0, 12));
                    return;
                }
                resolve(hex);
            }
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file.slice(0, 4));
    });
}

// Valores permitidos (validaÃ§Ã£o por whitelist)
const VALID_TIPOS = ['Carga Leve', 'Fracionada', 'Carga Fechada', 'Complemento'];
const VALID_VEICULOS = ['3/4', 'Toco', 'Fiorino', 'Truck', 'Bitruck', 'Carreta LS', 'Bitrem', 'Rodotrem', 'VanderlÃ©ia', 'CaÃ§amba', 'Silo', 'Graneleiro', 'Plataforma', 'Prancha', 'Tanque', 'Sider', 'BaÃº Refrigerado', 'BaÃº'];

// ====== SESSION TIMEOUT (24 hours) ======
let sessionTimer = null;
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
let currentShipperHistoryTab = 'concluida';

function resetSessionTimer() {
    if (sessionTimer) clearTimeout(sessionTimer);
    sessionTimer = setTimeout(() => {
        if (auth.currentUser) {
            showToast('SessÃ£o expirada por inatividade.', 'info');
            logout();
        }
    }, SESSION_TIMEOUT);
}

// Reset timer on user activity
['click', 'keypress', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetSessionTimer, { passive: true });
});

// ====== FUNÃ‡Ã•ES DE SEGURANÃ‡A ======

// Toggle visibilidade da senha aprimorado
function togglePassVisibility(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'ph ph-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'ph ph-eye';
    }
}

// Previne XSS: escapa caracteres HTML perigosos
function sanitizeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ValidaÃ§Ã£o de e-mail
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// ValidaÃ§Ã£o algorÃ­tmica de CPF
function validateCPF(cpf) {
    cpf = cpf.replace(/\D/g, '');
    if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
    let soma = 0, resto;
    for (let i = 1; i <= 9; i++) soma += parseInt(cpf[i - 1]) * (11 - i);
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    if (resto !== parseInt(cpf[9])) return false;
    soma = 0;
    for (let i = 1; i <= 10; i++) soma += parseInt(cpf[i - 1]) * (12 - i);
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    return resto === parseInt(cpf[10]);
}

// ValidaÃ§Ã£o algorÃ­tmica de CNPJ
function validateCNPJ(cnpj) {
    cnpj = cnpj.replace(/\D/g, '');
    if (cnpj.length !== 14 || /^(\d)\1{13}$/.test(cnpj)) return false;
    const pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const pesos2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let soma = 0;
    for (let i = 0; i < 12; i++) soma += parseInt(cnpj[i]) * pesos1[i];
    let resto = soma % 11;
    if (parseInt(cnpj[12]) !== (resto < 2 ? 0 : 11 - resto)) return false;
    soma = 0;
    for (let i = 0; i < 13; i++) soma += parseInt(cnpj[i]) * pesos2[i];
    resto = soma % 11;
    return parseInt(cnpj[13]) === (resto < 2 ? 0 : 11 - resto);
}

let fretes = [
    { id: 1, origem: 'Salvador', destino: 'Alagoinhas', valor: '620,00', tipo: 'Carga Leve', veiculo: 'VUC', status: 'transito', obs: 'Mercadoria alocada em paletes.' },
    { id: 2, origem: 'Salvador', destino: 'IlhÃ©us', valor: '980,00', tipo: 'Fracionada', veiculo: 'Toco', status: 'pendente', obs: 'Carga urgente para hoje.' }
];

let mensagens = [];
let systemMessages = [];
let systemMessagesListener = null;

window.onload = () => {
    renderChats();
    navTo('splash');
    
    // Inicializa Mapa Leaflet e Autocomplete do IBGE (100% Gratuito)
    if (typeof window.initLeafletMap === 'function') window.initLeafletMap();
    if (typeof window.setupIBGEAutocomplete === 'function') window.setupIBGEAutocomplete();

    // Catch possible redirect errors
    auth.getRedirectResult().then((result) => {
        if (result && result.user) {
            console.log("Redirect login successful");
            showToast('Login com Google realizado!', 'success');
        }
    }).catch((error) => {
        console.error("Erro no Redirect Sign-in:", error);
        showToast(`Falha na autenticaÃ§Ã£o: ${error.message}`, 'error');
    });

    // Monitora o estado de autenticaÃ§Ã£o via Firebase
    auth.onAuthStateChanged(async (user) => {
        if (isRegisteringProcess) {
            console.log("Ignorando redirecionamento automÃ¡tico do onAuthStateChanged durante o cadastro.");
            return;
        }
        if (user) {
            try {
                // Sincroniza/Salva a entrada em public_emails para garantir que o fluxo de verificaÃ§Ã£o funcione
                if (user.email) {
                    const emailKey = user.email.toLowerCase().trim();
                    const providerId = user.providerData[0]?.providerId === 'google.com' ? 'google' : 'password';
                    db.collection("public_emails").doc(emailKey).set({
                        provider: providerId
                    }, { merge: true }).catch(err => console.warn("Erro ao salvar public_emails:", err));
                }

                const userRef = db.collection("users").doc(user.uid);
                
                // Add a global variable to store the unubscribe function so we can clean it up
                if (window.userDocListener) {
                    window.userDocListener();
                }

                window.userDocListener = userRef.onSnapshot((doc) => {
                    if (doc.exists) {
                        userData = doc.data();
                        // SE O USUÃRIO FOR ADMIN, ELE Ã‰ TRATADO COMO EMBARCADOR (SHIPPER) NO APP PRINCIPAL
                        if (userData.role === 'admin') {
                            userData.role = 'shipper';
                        }
                        preencherPerfil();
                        setRole(userData.role || 'driver');
                        
                        // Start these only once, not on every user update, to avoid duplicate listeners
                        if (!window.freightListenerStarted) {
                            startFreightListener();
                            startSystemMessagesListener();
                            window.freightListenerStarted = true;
                        }
                    } else {
                        // Se logou com Google mas nÃ£o tem perfil, vai escolher o papel
                        if (window.userDocListener) window.userDocListener(); // stop listening
                        preencherCamposCadastroGoogle(user);
                        navTo('choice');
                    }
                }, (error) => {
                    console.error("Erro no listener do usuÃ¡rio:", error);
                });
                
            } catch (error) {
                console.error("Erro ao verificar documento do usuÃ¡rio:", error);
                showToast(`Erro na validaÃ§Ã£o do perfil: ${error.message}`, 'error');
                if (typeof restaurarBotaoGoogle === 'function') restaurarBotaoGoogle();
                navTo('auth_entry');
            }
        } else {
            if (systemMessagesListener) {
                systemMessagesListener();
                systemMessagesListener = null;
            }
            if (window.userDocListener) {
                window.userDocListener();
                window.userDocListener = null;
            }
            window.freightListenerStarted = false;
            restaurarBotoesCadastroPadrao();
            navTo('auth_entry');
        }
    });
};

// ====== LÃ“GICA DE AUTENTICAÃ‡ÃƒO (NOVA) ======

async function verificarEmailDisponivel(email) {
    const emailKey = email.toLowerCase().trim();
    
    // Se o usuÃ¡rio logado no Firebase Auth tem o mesmo e-mail, estÃ¡ tudo bem (ele estÃ¡ apenas completando o perfil)
    if (auth.currentUser && auth.currentUser.email && auth.currentUser.email.toLowerCase().trim() === emailKey) {
        return { disponivel: true };
    }
    
    try {
        const doc = await db.collection('public_emails').doc(emailKey).get();
        if (doc.exists) {
            const data = doc.data();
            return { disponivel: false, provider: data.provider };
        }
    } catch (e) {
        console.warn("Erro ao verificar email em public_emails:", e);
    }

    // Fallback secundÃ¡rio para fetchSignInMethodsForEmail
    try {
        const methods = await auth.fetchSignInMethodsForEmail(emailKey);
        if (methods && methods.length > 0) {
            const provider = (methods.includes('google.com') || methods.includes('google')) ? 'google' : 'password';
            return { disponivel: false, provider: provider };
        }
    } catch (authErr) {
        console.warn("Erro no fetchSignInMethodsForEmail:", authErr);
    }

    return { disponivel: true };
}

function preencherCamposCadastroGoogle(user) {
    if (!user) return;
    
    const regShipperNameEl = document.getElementById('regShipperName');
    if (regShipperNameEl) regShipperNameEl.value = user.displayName || '';
    
    const regShipperEmailEl = document.getElementById('regShipperEmail');
    if (regShipperEmailEl) {
        regShipperEmailEl.value = user.email || '';
        regShipperEmailEl.disabled = true;
    }

    const regDriverNameEl = document.getElementById('regDriverName');
    if (regDriverNameEl) regDriverNameEl.value = user.displayName || '';
    
    const regDriverEmailEl = document.getElementById('regDriverEmail');
    if (regDriverEmailEl) {
        regDriverEmailEl.value = user.email || '';
        regDriverEmailEl.disabled = true;
    }

    // Altera texto dos botÃµes de cadastro para Google
    const btnAvancarShipper = document.querySelector('#register_shipper button.btn-orange');
    if (btnAvancarShipper) {
        btnAvancarShipper.innerHTML = `Finalizar Cadastro <i class="ph ph-check-circle"></i>`;
    }
    const btnAvancarVehicle = document.querySelector('#register_vehicle button.btn-orange');
    if (btnAvancarVehicle) {
        btnAvancarVehicle.innerHTML = `Finalizar Cadastro <i class="ph ph-check-circle"></i>`;
    }
}

function restaurarBotaoGoogle() {
    const btnGoogle = document.querySelector('.btn-google');
    if (btnGoogle) {
        btnGoogle.innerHTML = `
            <svg width="22" height="22" viewBox="0 0 48 48" style="margin-right: 12px; flex-shrink: 0;">
                <path fill="#EA4335"
                    d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
                <path fill="#4285F4"
                    d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
                <path fill="#FBBC05"
                    d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
                <path fill="#34A853"
                    d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
            </svg>
            Entrar com Google`;
        btnGoogle.disabled = false;
    }
}

function restaurarBotoesCadastroPadrao() {
    const btnAvancarShipper = document.querySelector('#register_shipper button.btn-orange');
    if (btnAvancarShipper) {
        btnAvancarShipper.innerHTML = `PrÃ³xima Etapa <i class="ph ph-arrow-right"></i>`;
    }
    const btnAvancarVehicle = document.querySelector('#register_vehicle button.btn-orange');
    if (btnAvancarVehicle) {
        btnAvancarVehicle.innerHTML = `AvanÃ§ar para Senha <i class="ph ph-arrow-right"></i>`;
    }
    
    const regShipperEmailEl = document.getElementById('regShipperEmail');
    if (regShipperEmailEl) regShipperEmailEl.disabled = false;
    const regDriverEmailEl = document.getElementById('regDriverEmail');
    if (regDriverEmailEl) regDriverEmailEl.disabled = false;

    restaurarBotaoGoogle();
}

async function finalizarCadastroGoogle() {
    const user = auth.currentUser;
    if (!user) {
        showToast('UsuÃ¡rio nÃ£o autenticado.', 'error');
        return;
    }

    const uid = user.uid;

    const cleanUserData = {};
    Object.keys(userData).forEach(key => {
        if (userData[key] !== undefined && userData[key] !== null) {
            cleanUserData[key] = userData[key];
        }
    });

    cleanUserData.role = tempRole;
    cleanUserData.rating = 5.0;
    cleanUserData.entregas = 0;
    
    if (!cleanUserData.email) {
        cleanUserData.email = user.email;
    }

    // 1. Salva o perfil do usuÃ¡rio no Firestore
    await db.collection("users").doc(uid).set(cleanUserData);
    userData = cleanUserData;

    // 2. Salva em public_emails para controle de login manual
    const emailKey = cleanUserData.email.toLowerCase().trim();
    await db.collection("public_emails").doc(emailKey).set({
        provider: 'google'
    }, { merge: true }).catch(err => console.warn("Erro ao salvar public_emails:", err));

    isRegisteringProcess = false;
    preencherPerfil();
    setRole(tempRole);
    showToast('Cadastro realizado com sucesso! Bem-vindo ao PegaFrete.');
}

async function handleContinuar(btn) {
    const email = document.getElementById('authEmail').value.trim();
    if (!email || !validateEmail(email)) {
        showToast('Por favor, insira um e-mail vÃ¡lido.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Verificando...`;
    btn.disabled = true;

    try {
        // Pre-fill email in all forms
        document.getElementById('loginEmail').value = email;
        if (document.getElementById('regShipperEmail')) {
            document.getElementById('regShipperEmail').value = email;
        }
        if (document.getElementById('regDriverEmail')) {
            document.getElementById('regDriverEmail').value = email;
        }

        // Verifica se o e-mail jÃ¡ possui conta vinculada
        const check = await verificarEmailDisponivel(email);
        
        btn.innerHTML = original;
        btn.disabled = false;

        if (!check.disponivel) {
            navTo('login');
        } else {
            navTo('choice');
        }
    } catch (error) {
        console.warn("Erro no handleContinuar, usando fallback seguro:", error);
        btn.innerHTML = original;
        btn.disabled = false;
        // Secure fallback
        navTo('login');
    }
}

async function loginComGoogle(btn) {
    const provider = new firebase.auth.GoogleAuthProvider();
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Conectando...`;
    btn.disabled = true;

    try {
        // Usa popup para garantir que cookies de terceiros nÃ£o bloqueiem a sessÃ£o
        const result = await auth.signInWithPopup(provider);
        console.log("Login com popup bem sucedido:", result.user.email);
        // O onAuthStateChanged cuidarÃ¡ do redirecionamento
    } catch (error) {
        console.error("Erro no Google Sign-in:", error);
        btn.innerHTML = original;
        btn.disabled = false;
        if (error.code !== 'auth/popup-closed-by-user') {
            showToast(`Erro ao entrar com Google: ${error.message}`, 'error');
        } else {
            showToast('O popup de login foi fechado antes de concluir.', 'error');
        }
    }
}

let freightListenerUnsubscribe = null;

// Escuta novas cargas em tempo real
function startFreightListener() {
    if (freightListenerUnsubscribe) {
        freightListenerUnsubscribe(); // Previne mÃºltiplos listeners
    }
    let isInitialLoad = true;
    
    freightListenerUnsubscribe = db.collection("freights").orderBy("createdAt", "desc").limit(20).onSnapshot((snapshot) => {
        const novosDados = [];
        snapshot.forEach(doc => novosDados.push({ id: doc.id, ...doc.data() }));

        // Verifica se hÃ¡ novas cargas para notificar (se nÃ£o for a carga que eu acabei de postar)
        if (!isInitialLoad && fretes.length > 0 && novosDados.length > fretes.length) {
            const ultimaCarga = novosDados[0];
            if (userData && userData.role === 'driver' && window.isDriverOnline && ultimaCarga.shipperUid !== auth.currentUser?.uid) {
                showToast(`Nova carga disponÃ­vel: ${ultimaCarga.origem} para ${ultimaCarga.destino}`, 'info');
            }
        }
        isInitialLoad = false;

        fretes = novosDados;
        renderFretes();
    });
}

function maskMoney(i) {
    let v = i.value.replace(/\D/g, "");
    v = (v / 100).toFixed(2) + "";
    v = v.replace(".", ",");
    v = v.replace(/(\d)(\d{3})(\d{3}),/g, "$1.$2.$3,");
    v = v.replace(/(\d)(\d{3}),/g, "$1.$2,");
    i.value = "R$ " + v;
}

function maskPhone(i) {
    let v = i.value.replace(/\D/g, "");
    if (v.length > 11) v = v.slice(0, 11);

    if (v.length === 0) {
        i.value = "";
        return;
    }

    if (v.length <= 2) {
        i.value = `(${v}`;
    } else if (v.length <= 6) {
        i.value = `(${v.slice(0, 2)}) ${v.slice(2)}`;
    } else if (v.length <= 10) {
        i.value = `(${v.slice(0, 2)}) ${v.slice(2, 6)}-${v.slice(6)}`;
    } else {
        i.value = `(${v.slice(0, 2)}) ${v.slice(2, 7)}-${v.slice(7)}`;
    }
}

function maskCPF(i) {
    let v = i.value.replace(/\D/g, "");
    if (v.length > 11) v = v.slice(0, 11);
    if (v.length === 11) {
        i.value = v.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
    } else {
        i.value = v;
    }
}

function maskCNPJ(i) {
    let v = i.value.replace(/\D/g, "");
    if (v.length > 14) v = v.slice(0, 14);
    if (v.length === 14) {
        i.value = v.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/, "$1.$2.$3/$4-$5");
    } else {
        i.value = v;
    }
}

function checkPasswordRequirements(val) {
    const len = val.length >= 8;
    const upper = /[A-Z]/.test(val);
    const num = /[0-9]/.test(val);
    const special = /[!@#$%^&*(),.?":{}|<>]/.test(val);

    const updateReq = (id, met) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (met) {
            el.style.color = '#10b981';
            el.querySelector('i').className = 'ph-fill ph-check-circle';
        } else {
            el.style.color = 'var(--text-muted)';
            el.querySelector('i').className = 'ph ph-circle';
        }
    };

    updateReq('req-len', len);
    updateReq('req-upper', upper);
    updateReq('req-number', num);
    updateReq('req-special', special);
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const safeMessage = sanitizeHTML(message);
    let icon = type === 'success'
        ? '<i class="ph-fill ph-check-circle" style="color: #22c55e; font-size: 20px;"></i>'
        : type === 'error'
            ? '<i class="ph-fill ph-warning-circle" style="color: #ef4444; font-size: 20px;"></i>'
            : '<i class="ph-fill ph-info" style="color: #3b82f6; font-size: 20px;"></i>';

    toast.innerHTML = `${icon} <span>${safeMessage}</span>`;
    toast.classList.add('show');

    setTimeout(() => { toast.classList.remove('show'); }, 3000);
}

function navTo(id, pushState = true) {
    // Gerenciamento da flag isRegisteringProcess para evitar auto-redirecionamento da sessÃ£o
    if (['choice', 'register_shipper', 'register_driver', 'register_vehicle', 'register_password'].includes(id)) {
        isRegisteringProcess = true;
    } else if (['auth_entry', 'login', 'driver', 'shipper', 'profile', 'chat', 'financial'].includes(id)) {
        isRegisteringProcess = false;
    }

    if (navHistory[navHistory.length - 1] !== id) navHistory.push(id);
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    window.scrollTo(0, 0);
    updateNavbar(id);

    if (id === 'shipper_publish') {
        if (typeof resetPublishStep === 'function') {
            resetPublishStep();
        }
    }

    if (pushState) {
        window.history.pushState({ screen: id }, "", `#${id}`);
    }
}

function goBack() {
    if (navHistory.length > 1) {
        window.history.back();
    }
}

window.addEventListener('popstate', (event) => {
    if (event.state && event.state.screen) {
        const target = event.state.screen;
        if (navHistory.length > 1) navHistory.pop();
        document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
        document.getElementById(target).classList.add('active');
        window.scrollTo(0, 0);
        updateNavbar(target);
    } else {
        if (navHistory.length > 1) navHistory.pop();
        const fallback = navHistory[navHistory.length - 1] || 'auth_entry';
        document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
        document.getElementById(fallback).classList.add('active');
        window.scrollTo(0, 0);
        updateNavbar(fallback);
    }
});

function goHome() {
    if (currentUserRole) navTo(currentUserRole);
    else navTo('choice');
}

function setRole(role) {
    currentUserRole = role;

    // Altera Navbar com base na Role
    document.querySelectorAll('.driver-only').forEach(el => el.style.display = role === 'driver' ? 'flex' : 'none');
    document.querySelectorAll('.shipper-only').forEach(el => el.style.display = role === 'shipper' ? 'flex' : 'none');

    // Altera texto do botÃ£o de perfil
    const changeRoleText = document.getElementById('changeRoleText');
    if (changeRoleText) {
        changeRoleText.innerText = role === 'driver' ? 'Mudar para Embarcador' : 'Mudar para Transportador';
    }

    navHistory = ['login', 'choice', role];
    navTo(role);
}

function updateNavbar(id) {
    const nav = document.getElementById('bottomNav');
    const screensWithNav = ['driver', 'shipper', 'profile', 'financial', 'chat', 'freights_search', 'shipper_history', 'shipper_publish'];

    if (screensWithNav.includes(id)) {
        nav.style.display = 'flex';
        document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));

        let navId = id;
        if (id === 'driver' || id === 'shipper') navId = 'home';
        if (id === 'freights_search') navId = 'freights';
        if (id === 'shipper_history') navId = 'my_freights';
        if (id === 'shipper_publish') navId = 'shipper_publish';

        const activeItem = document.querySelector(`.nav-item[data-target="${navId}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
        }
    } else {
        nav.style.display = 'none';
    }
}

// Modal de Filtros (Cargas)
function openFilters() { document.getElementById('filterModal').classList.add('active'); }
function closeFilters() { document.getElementById('filterModal').classList.remove('active'); }
function aplicarFiltros() {
    closeFilters();
    showToast('Filtros aplicados com sucesso!', 'success');
}
function limparFiltros() {
    document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
    document.getElementById('distSlider').value = 250;
    document.getElementById('distValue').innerText = '250 km';
}
function togglePill(pill) { pill.classList.toggle('active'); }

// Modal de EdiÃ§Ã£o (Embarcador)
let currentEditId = null;
function abrirEdicaoFrete(id) {
    const f = fretes.find(x => x.id === id);
    if (!f) return;
    currentEditId = id;
    document.getElementById('editOrigem').value = f.origem;
    document.getElementById('editDestino').value = f.destino;
    document.getElementById('editValor').value = "R$ " + f.valor;
    document.getElementById('editTipo').value = f.tipo;
    document.getElementById('editVeiculo').value = f.veiculo;
    document.getElementById('editObs').value = f.obs || '';
    document.getElementById('editFreightModal').classList.add('active');
}
function fecharEdicaoFrete() {
    document.getElementById('editFreightModal').classList.remove('active');
}
async function salvarEdicaoFrete(btn) {
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Salvando...`;
    btn.disabled = true;

    try {
        const updatedData = {
            origem: sanitizeInput(document.getElementById('editOrigem').value.trim(), 200),
            destino: sanitizeInput(document.getElementById('editDestino').value.trim(), 200),
            valor: sanitizeInput(document.getElementById('editValor').value.replace('R$ ', '').trim(), 20),
            tipo: document.getElementById('editTipo').value,
            veiculo: document.getElementById('editVeiculo').value,
            obs: sanitizeInput(document.getElementById('editObs').value.trim(), 500)
        };

        // Whitelist validation
        if (!VALID_TIPOS.includes(updatedData.tipo) || !VALID_VEICULOS.includes(updatedData.veiculo)) {
            showToast('Tipo de carga ou veÃ­culo invÃ¡lido.', 'error');
            logSecurityEvent('INVALID_INPUT', `Tipo de carga ou veÃ­culo invÃ¡lido editado por ${auth.currentUser?.uid}`);
            btn.innerHTML = original;
            btn.disabled = false;
            return;
        }

        if (typeof currentEditId === 'string') {
            // Firestore protegido por Security Rules (ownership check server-side)
            updatedData.updatedAt = firebase.firestore.FieldValue.serverTimestamp();
            await db.collection('freights').doc(currentEditId).update(updatedData);
        }

        // Atualiza local (real-time listener will also update)
        const f = fretes.find(x => x.id === currentEditId);
        if (f) Object.assign(f, updatedData);

        btn.innerHTML = original;
        btn.disabled = false;
        fecharEdicaoFrete();
        renderFretes();
        showToast('As informaÃ§Ãµes da carga foram atualizadas.');
    } catch (error) {
        btn.innerHTML = original;
        btn.disabled = false;
        showToast(error.message || 'Erro ao salvar alteraÃ§Ãµes.', 'error');
    }
}


let confirmationResult = null; // Armazena o resultado do envio de SMS do Firebase

async function verificarTelefone(btn) {
    if (smsSendCooldown) {
        showToast('Aguarde 60 segundos antes de reenviar o SMS.', 'error');
        return;
    }

    const rawPhone = document.getElementById('checkPhone').value;
    const phoneInput = "+55" + rawPhone.replace(/\D/g, "");

    if (phoneInput.length < 13) {
        showToast('Insira um nÃºmero vÃ¡lido.', 'error');
        return;
    }

    tempPhone = rawPhone;
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Enviando SMS...`;
    btn.disabled = true;

    try {
        if (!window.recaptchaVerifier) {
            window.recaptchaVerifier = new firebase.auth.RecaptchaVerifier('recaptcha-container', {
                'size': 'invisible'
            });
        }

        confirmationResult = await auth.signInWithPhoneNumber(phoneInput, window.recaptchaVerifier);

        // Ativa cooldown de 60 segundos
        smsSendCooldown = true;
        setTimeout(() => { smsSendCooldown = false; }, 60000);

        btn.innerHTML = original;
        btn.disabled = false;
        showToast('CÃ³digo enviado com sucesso!', 'success');
        navTo('otp_verify');
    } catch (error) {
        btn.innerHTML = original;
        btn.disabled = false;
        showToast('Erro ao enviar SMS. Tente novamente.', 'error');
    }
}

async function confirmarCodigo(btn) {
    const code = document.getElementById('otpCode').value;
    if (code.length !== 6) {
        showToast('O cÃ³digo deve ter 6 dÃ­gitos.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;

    try {
        // Confirma o cÃ³digo no Firebase
        const userCredential = await confirmationResult.confirm(code);
        const user = userCredential.user;

        btn.innerHTML = original;

        // Agora que o telefone estÃ¡ validado, verificamos se ele jÃ¡ tem um perfil no banco
        const querySnapshot = await db.collection("users").where("telefone", "==", tempPhone).get();

        if (!querySnapshot.empty) {
            // JÃ¡ tem cadastro, vai pro Login (onde ele pÃµe o email e a senha que ele criou antes)
            // Ou podemos fazer o login direto se ele jÃ¡ tiver email salvo, mas o usuÃ¡rio pediu senha.
            navTo('login');
        } else {
            // Não tem cadastro, vai escolher o perfil
            navTo('choice');
        }
    } catch (error) {
        btn.innerHTML = original;
        showToast('CÃ³digo invÃ¡lido ou expirado.', 'error');
    }
}

async function fazerLogin(btn) {
    // RATE LIMITING PROTECTION (BRUTE FORCE)
    const now = Date.now();
    if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        if (now - lastLoginAttemptTime < LOGIN_COOLDOWN_MS) {
            const timeLeft = Math.ceil((LOGIN_COOLDOWN_MS - (now - lastLoginAttemptTime)) / 1000);
            showToast(`Muitas tentativas. Aguarde ${timeLeft} segundos.`, 'error');
            return;
        } else {
            loginAttempts = 0; // reset after cooldown
        }
    }

    const email = document.getElementById('loginEmail').value;
    const pass = document.getElementById('loginPassword').value;

    if (!email || !pass) {
        showToast('Preencha os campos corretamente.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Autenticando...`;
    
    lastLoginAttemptTime = now;
    loginAttempts++;

    try {
        const userCredential = await auth.signInWithEmailAndPassword(email, pass);
        const docRef = await db.collection("users").doc(userCredential.user.uid).get();
        btn.innerHTML = original;

        if (docRef.exists) {
            userData = docRef.data();
            // SE O USUÃRIO FOR ADMIN, ELE Ã‰ TRATADO COMO EMBARCADOR (SHIPPER) NO APP PRINCIPAL
            if (userData.role === 'admin') {
                userData.role = 'shipper';
            }
            preencherPerfil();
            setRole(userData.role || 'driver');
            showToast('Bem-vindo de volta!');
        } else {
            showToast('Perfil de usuÃ¡rio nÃ£o encontrado.', 'error');
        }
    } catch (error) {
        btn.innerHTML = original;
        // SECURITY: Generic error message to prevent credential enumeration
        // Don't distinguish between "user not found" and "wrong password"
        if (error.code === 'auth/user-not-found' || error.code === 'auth/invalid-credential') {
            showToast('Credenciais invÃ¡lidas. Verifique seu e-mail e senha.', 'error');
            // Offer registration option without confirming if email exists
            const registerLink = document.createElement('div');
            registerLink.style.cssText = 'text-align:center; margin-top:12px;';
            registerLink.innerHTML = '<a href="#" onclick="navTo(\'choice\')" style="color:var(--orange); font-weight:600; text-decoration:none;">Criar uma nova conta</a>';
        } else if (error.code === 'auth/too-many-requests') {
            showToast('Muitas tentativas. Aguarde antes de tentar novamente.', 'error');
        } else {
            showToast('Erro ao fazer login. Tente novamente.', 'error');
        }
    }
}

function iniciarCadastro(role) {
    tempRole = role;
    if (role === 'shipper') navTo('register_shipper');
    else navTo('register_driver');
}

async function irParaVeiculo(btn) {
    userData.nome = document.getElementById('regDriverName').value.trim();
    userData.email = document.getElementById('regDriverEmail').value.trim();
    userData.telefone = document.getElementById('regDriverPhone').value.trim();
    userData.endereco = document.getElementById('regDriverAddress').value.trim();
    userData.cpf = document.getElementById('regDriverCpf').value.trim();

    if (!userData.nome || !userData.email || !userData.telefone) {
        showToast('Preencha pelo menos os campos obrigatÃ³rios.', 'error');
        return;
    }
    if (!validateEmail(userData.email)) {
        showToast('Insira um e-mail vÃ¡lido.', 'error');
        return;
    }
    if (userData.cpf && !validateCPF(userData.cpf)) {
        showToast('CPF invÃ¡lido. Verifique os dÃ­gitos.', 'error');
        return;
    }

    const originalText = btn ? btn.innerHTML : 'PrÃ³xima Etapa';
    if (btn) {
        btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;
        btn.disabled = true;
    }

    try {
        const check = await verificarEmailDisponivel(userData.email);
        if (!check.disponivel) {
            if (check.provider === 'google') {
                showToast('Este e-mail jÃ¡ estÃ¡ cadastrado via Google. FaÃ§a login com o Google.', 'error');
            } else {
                showToast('Este e-mail jÃ¡ estÃ¡ cadastrado. FaÃ§a login ou use outro e-mail.', 'error');
            }
            if (btn) {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
            return;
        }
    } catch (err) {
        console.warn("Erro ao verificar disponibilidade do e-mail:", err);
    }

    if (btn) {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
    navTo('register_vehicle');
}

window.irParaDocs = irParaDocs;
async function irParaDocs(btn) {
    const selObj = document.getElementById('regDriverVehicle');
    const opt = selObj.options[selObj.selectedIndex];
    if (opt.disabled || opt.value === "") {
        showToast('Por favor, selecione o seu veÃ­culo.', 'error');
        return;
    }
    userData.veiculo = opt.value;
    navTo('register_driver_docs');
}

async function irParaSenha(btn) {
    if (tempRole === 'shipper') {
        userData.nome = document.getElementById('regShipperName').value.trim();
        userData.email = document.getElementById('regShipperEmail').value.trim();
        userData.telefone = document.getElementById('regShipperPhone').value.trim();
        userData.endereco = document.getElementById('regShipperAddress').value.trim();
        userData.cnpj = document.getElementById('regShipperCnpj').value.trim();
        userData.razao = document.getElementById('regShipperRazao').value.trim();

        if (!userData.nome || !userData.email || !userData.telefone) {
            showToast('Preencha pelo menos os campos obrigatÃ³rios.', 'error');
            return;
        }
        if (!validateEmail(userData.email)) {
            showToast('Insira um e-mail vÃ¡lido.', 'error');
            return;
        }
        if (userData.cnpj && !validateCNPJ(userData.cnpj)) {
            showToast('CNPJ invÃ¡lido. Verifique os dÃ­gitos.', 'error');
            return;
        }

        const originalText = btn ? btn.innerHTML : 'PrÃ³xima Etapa';
        if (btn) {
            btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;
            btn.disabled = true;
        }

        try {
            const check = await verificarEmailDisponivel(userData.email);
            if (!check.disponivel) {
                if (check.provider === 'google') {
                    showToast('Este e-mail jÃ¡ estÃ¡ cadastrado via Google. FaÃ§a login com o Google.', 'error');
                } else {
                    showToast('Este e-mail jÃ¡ estÃ¡ cadastrado. FaÃ§a login ou use outro e-mail.', 'error');
                }
                if (btn) {
                    btn.innerHTML = originalText;
                    btn.disabled = false;
                }
                return;
            }
        } catch (err) {
            console.warn("Erro ao verificar disponibilidade do e-mail:", err);
        }

        if (btn) {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    } else {
        const antt = document.getElementById('regDriverAntt').value.trim();
        const cnh = document.getElementById('regDriverCnh').value.trim();
        const placa = document.getElementById('regDriverPlaca').value.trim();
        const fileCnhFrente = document.getElementById('regDriverCnhFrente').files[0];
        const fileCnhVerso = document.getElementById('regDriverCnhVerso').files[0];
        const fileCpfFrente = document.getElementById('regDriverCpfFrente').files[0];
        const fileCpfVerso = document.getElementById('regDriverCpfVerso').files[0];

        if (!antt || !cnh || !placa || !fileCnhFrente || !fileCnhVerso || !fileCpfFrente || !fileCpfVerso) {
            showToast('Preencha todos os campos e envie as fotos frente e verso para prosseguir.', 'error');
            return;
        }

        const originalText = btn ? btn.innerHTML : 'AvanÃ§ar para Senha';
        if (btn) {
            btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;
            btn.disabled = true;
        }

        const valid1 = await validateFile(fileCnhFrente);
        const valid2 = await validateFile(fileCnhVerso);
        const valid3 = await validateFile(fileCpfFrente);
        const valid4 = await validateFile(fileCpfVerso);

        if (btn) {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }

        if (!valid1.valid || !valid2.valid || !valid3.valid || !valid4.valid) {
            showToast('Erro na validaÃ§Ã£o das fotos. Verifique o formato e o tamanho.', 'error');
            return;
        }

        userData.antt = antt;
        userData.cnh = cnh;
        userData.placa = placa;
        userData.docStatus = 'Pendente';
        userData.filesToUpload = {
            cnhFrente: fileCnhFrente,
            cnhVerso: fileCnhVerso,
            cpfFrente: fileCpfFrente,
            cpfVerso: fileCpfVerso
        };
    }

    navTo('register_password');
}

window.concluirDepoisDocs = concluirDepoisDocs;
function concluirDepoisDocs() {
    userData.docStatus = 'DocumentaÃ§Ã£o Incompleta';
    navTo('register_password');
}

async function finalizarCadastro(btn) {
    const pass1 = document.getElementById('regPassword').value;
    const pass2 = document.getElementById('regPasswordConfirm').value;

    // ValidaÃ§Ã£o de senha: 8 dÃ­gitos, letra maiÃºscula, nÃºmero, caractere especial
    const passRegex = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;
    if (!passRegex.test(pass1)) {
        showToast('A senha nÃ£o cumpre os requisitos de seguranÃ§a.', 'error');
        return;
    }

    if (pass1 !== pass2) {
        showToast('As senhas nÃ£o coincidem.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Criando conta...`;

    try {
        let uid;
        if (auth.currentUser) {
            // Se logou com Google, a conta jÃ¡ existe no Firebase Auth.
            // Apenas adicionamos a senha para garantir o acesso tambÃ©m via E-mail/Senha.
            await auth.currentUser.updatePassword(pass1);
            uid = auth.currentUser.uid;
        } else {
            // Fluxo normal: Cria o usuÃ¡rio na Auth do Firebase
            const userCredential = await auth.createUserWithEmailAndPassword(userData.email, pass1);
            uid = userCredential.user.uid;
        }

        // Sanitiza o objeto para remover campos undefined ou null para evitar erros do Firestore
        const cleanUserData = {};
        Object.keys(userData).forEach(key => {
            if (userData[key] !== undefined && userData[key] !== null) {
                cleanUserData[key] = userData[key];
            }
        });

        cleanUserData.role = tempRole;
        cleanUserData.rating = 5.0;
        cleanUserData.entregas = 0;
        if (userData.docStatus) {
            cleanUserData.docStatus = userData.docStatus;
        }

        // Upload files if pending (Using Local Compression to avoid Firebase Storage Pricing/CORS)
        if (cleanUserData.role === 'driver' && cleanUserData.docStatus === 'Pendente' && userData.filesToUpload) {
            showToast('Processando e enviando documentos, aguarde...');
            try {
                const compressImageToBase64 = (file, maxWidth = 800) => {
                    return new Promise((resolve, reject) => {
                        if (!file || !file.type.match(/image.*/)) {
                            const reader = new FileReader();
                            reader.onload = e => resolve(e.target.result);
                            reader.onerror = error => reject(error);
                            if(file) reader.readAsDataURL(file); else resolve(null);
                            return;
                        }
                        const reader = new FileReader();
                        reader.onload = function(event) {
                            const img = new Image();
                            img.onload = function() {
                                const canvas = document.createElement('canvas');
                                let width = img.width;
                                let height = img.height;
                                if (width > maxWidth) {
                                    height = Math.round(height * maxWidth / width);
                                    width = maxWidth;
                                }
                                canvas.width = width;
                                canvas.height = height;
                                const ctx = canvas.getContext('2d');
                                ctx.drawImage(img, 0, 0, width, height);
                                resolve(canvas.toDataURL('image/jpeg', 0.6));
                            };
                            img.onerror = error => reject(error);
                            img.src = event.target.result;
                        };
                        reader.readAsDataURL(file);
                    });
                };

                const uploads = userData.filesToUpload;
                
                const cnhFrenteUrl = await compressImageToBase64(uploads.cnhFrente);
                const cnhVersoUrl = await compressImageToBase64(uploads.cnhVerso);
                const cpfFrenteUrl = await compressImageToBase64(uploads.cpfFrente);
                const cpfVersoUrl = await compressImageToBase64(uploads.cpfVerso);
                
                cleanUserData.documentUrls = {
                    cnhFrente: cnhFrenteUrl,
                    cnhVerso: cnhVersoUrl,
                    cpfFrente: cpfFrenteUrl,
                    cpfVerso: cpfVersoUrl
                };
            } catch (err) {
                console.error("Erro no upload", err);
                showToast('Aviso: Erro ao enviar fotos. Status ficarÃ¡ incompleto.', 'error');
                cleanUserData.docStatus = 'DocumentaÃ§Ã£o Incompleta';
            }
            delete userData.filesToUpload; // cleanup
        } else if (cleanUserData.role === 'driver') {
            cleanUserData.docStatus = 'DocumentaÃ§Ã£o Incompleta'; // fallback if no docs provided
        }

        // Verifica ConfiguraÃ§Ã£o Global de AprovaÃ§Ã£o AutomÃ¡tica (Modo Testes/HomologaÃ§Ã£o)
        if (cleanUserData.role === 'driver') {
            try {
                const configDoc = await db.collection("settings").doc("system_config").get();
                if (configDoc.exists && configDoc.data().autoApproveDrivers === true) {
                    cleanUserData.docStatus = 'Aprovado';
                }
            } catch (err) {
                console.warn("Erro ao ler configuraÃ§Ãµes globais de aprovaÃ§Ã£o:", err);
            }
        }

        // Salva no Firestore
        await db.collection("users").doc(uid).set(cleanUserData);
        userData = cleanUserData; // Atualiza a variÃ¡vel global

        // Salva em public_emails para controle de login manual
        const emailKey = cleanUserData.email.toLowerCase().trim();
        await db.collection("public_emails").doc(emailKey).set({
            provider: 'password'
        }, { merge: true }).catch(err => console.warn("Erro ao salvar public_emails:", err));

        isRegisteringProcess = false; // Finaliza o cadastro com sucesso
        btn.innerHTML = original;
        preencherPerfil();
        setRole(tempRole);
        showToast('Cadastro realizado com sucesso! Bem-vindo ao PegaFrete.');
    } catch (error) {
        btn.innerHTML = original;
        const errMsg = error.code === 'auth/email-already-in-use'
            ? 'Este e-mail jÃ¡ estÃ¡ em uso.'
            : error.code === 'auth/weak-password'
                ? 'A senha Ã© muito fraca.'
                : 'Erro ao criar conta. Verifique seus dados.';
        showToast(errMsg, 'error');
    }
}

async function salvarNovoEmail() {
    const novoEmail = document.getElementById('updateEmailInput').value.trim();
    if (!novoEmail || !validateEmail(novoEmail)) {
        showToast('Insira um e-mail vÃ¡lido.', 'error');
        return;
    }

    if (novoEmail === userData.email) {
        showToast('Este jÃ¡ Ã© o seu e-mail atual.', 'info');
        return;
    }

    const btn = document.getElementById('btnSaveEmail');
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Atualizando...`;
    btn.disabled = true;

    try {
        // Verificar se estÃ¡ disponÃ­vel
        const check = await verificarEmailDisponivel(novoEmail);
        if (!check.disponivel) {
            showToast('Este e-mail jÃ¡ estÃ¡ em uso.', 'error');
            btn.innerHTML = original;
            btn.disabled = false;
            return;
        }

        const user = auth.currentUser;
        if (!user) throw new Error("UsuÃ¡rio nÃ£o autenticado");

        // Atualizar no Firebase Auth
        await user.updateEmail(novoEmail);

        // Atualizar no Firestore users
        await db.collection('users').doc(user.uid).update({
            email: novoEmail
        });

        // Atualizar no public_emails (Remover antigo e adicionar novo)
        const oldEmailKey = userData.email.toLowerCase().trim();
        const newEmailKey = novoEmail.toLowerCase().trim();
        await db.collection("public_emails").doc(oldEmailKey).delete().catch(()=>console.warn("old email public_emails delete err"));
        await db.collection("public_emails").doc(newEmailKey).set({ provider: 'password' }, { merge: true }).catch(()=>console.warn("new email public_emails err"));

        userData.email = novoEmail;
        preencherPerfil();
        
        showToast('E-mail atualizado com sucesso!', 'success');
        setTimeout(() => navTo('profile'), 1500);

    } catch (error) {
        console.error("Erro ao atualizar e-mail:", error);
        if (error.code === 'auth/requires-recent-login') {
            showToast('Por seguranÃ§a, faÃ§a login novamente para trocar o e-mail.', 'error');
            setTimeout(() => {
                auth.signOut().then(() => window.location.reload());
            }, 2500);
        } else {
            showToast('Erro ao atualizar e-mail.', 'error');
        }
    } finally {
        if (btn) {
            btn.innerHTML = original;
            btn.disabled = false;
        }
    }
}

function preencherPerfil() {
    if (document.getElementById('profName')) document.getElementById('profName').value = userData.nome || '';

    if (userData.tipoDocumento === 'cnpj' || userData.cnpj) {
        if (document.getElementById('profRazaoGroup')) document.getElementById('profRazaoGroup').style.display = 'flex';
        if (document.getElementById('profDocLabel')) document.getElementById('profDocLabel').innerText = 'CNPJ';
        if (document.getElementById('profRazao')) document.getElementById('profRazao').value = userData.razao || '';
        if (document.getElementById('profDoc')) document.getElementById('profDoc').value = userData.cnpj || userData.documento || '';
    } else {
        if (document.getElementById('profRazaoGroup')) document.getElementById('profRazaoGroup').style.display = 'none';
        if (document.getElementById('profDocLabel')) document.getElementById('profDocLabel').innerText = 'CPF';
        if (document.getElementById('profDoc')) document.getElementById('profDoc').value = userData.cpf || userData.documento || '';
    }

    if (document.getElementById('profileDisplayName')) document.getElementById('profileDisplayName').innerText = userData.nome || userData.razao || 'UsuÃ¡rio';
    
    // New fields for the redesigned profile layout
    if (document.getElementById('profileEmailDisplay')) document.getElementById('profileEmailDisplay').innerText = userData.email || 'Email nÃ£o cadastrado';
    if (document.getElementById('updateEmailInput')) document.getElementById('updateEmailInput').value = userData.email || '';
    if (document.getElementById('profileRoleText')) {
        document.getElementById('profileRoleText').innerText = userData.role === 'shipper' ? 'Embarcador' : 'Transportador';
    }

    const profileTagContainer = document.getElementById('profileStatusTagContainer');
    const profileTagText = document.getElementById('profileStatusTagText');
    if (profileTagContainer && profileTagText) {
        let tagTitle = "";
        let colorMain = "#10b981";
        
        let docStat = userData.docStatus || 'Documentação Incompleta';
        
        if (docStat === 'Aprovado') {
            tagTitle = "Homologado";
            colorMain = "#10b981";
        } else if (docStat === 'Recusado') {
            tagTitle = "Recusado";
            colorMain = "#ef4444";
        } else if (docStat === 'Não Verificado') {
            tagTitle = "Não Verificado";
            colorMain = "#64748b";
        } else {
            tagTitle = "Pendente";
            colorMain = "#d97706";
        }

        profileTagText.innerText = tagTitle;
        profileTagText.style.color = colorMain;
    }
    if (document.getElementById('driverHomeGreeting')) {
        const firstName = (userData.nome || userData.razao || 'UsuÃ¡rio').split(' ')[0];
        document.getElementById('driverHomeGreeting').innerText = `OlÃ¡, ${firstName}`;
    }

        // --- NEW PDDATA INJECTION ---
    if (document.getElementById('pdFirstName')) {
        const parts = (userData.nome || userData.razao || 'Usuário').split(' ');
        document.getElementById('pdFirstName').innerText = parts[0];
        document.getElementById('pdLastName').innerText = parts.length > 1 ? parts.slice(1).join(' ') : '-';
        
        let docStr = userData.tipoDocumento === 'cnpj' ? (userData.cnpj || userData.documento || '') : (userData.cpf || userData.documento || '');
        if(docStr) {
            document.getElementById('pdDoc').innerText = docStr;
        }
        
        document.getElementById('pdPhone').innerText = userData.telefone || 'Adicionar';
        
        const emailEl = document.getElementById('pdEmail');
        if (userData.email) {
            const emParts = userData.email.split('@');
            if(emParts.length === 2 && emParts[0].length > 1) {
                emailEl.innerText = emParts[0].charAt(0) + '***@' + emParts[1];
            } else {
                emailEl.innerText = userData.email;
            }
        } else {
            emailEl.innerText = 'Adicionar';
        }

        const avatarUrl = userData.foto || 'https://i.imgur.com/vnYcevV.png';
        if(document.getElementById('pdAvatar')) {
            document.getElementById('pdAvatar').style.backgroundImage = "url('$"{avatarUrl}')";
        }

        const pdTagText = document.getElementById('pdStatusTagText');
        const pdTagWrap = document.getElementById('pdStatusTagWrapper');
        if (pdTagText && pdTagWrap) {
            let docStat = userData.docStatus || 'Documentação Incompleta';
            if (docStat === 'Aprovado') {
                pdTagText.innerText = "Homologado";
                pdTagText.style.color = "#10b981";
                pdTagWrap.style.borderColor = "#d1fae5";
            } else if (docStat === 'Recusado') {
                pdTagText.innerText = "Recusado";
                pdTagText.style.color = "#ef4444";
                pdTagWrap.style.borderColor = "#fecaca";
            } else if (docStat === 'Não Verificado') {
                pdTagText.innerText = "Não Verificado";
                pdTagText.style.color = "#64748b";
                pdTagWrap.style.borderColor = "#e2e8f0";
            } else {
                pdTagText.innerText = "Pendente";
                pdTagText.style.color = "#d97706";
                pdTagWrap.style.borderColor = "#fde68a";
            }
        }

        if (userData.role === 'driver') {
            document.getElementById('pdExtraBlock').style.display = 'block';
            document.getElementById('pdVehicle').innerText = userData.veiculo || 'Adicionar';
            document.getElementById('pdPlaca').innerText = userData.placa || 'Adicionar';
            document.getElementById('pdCnh').innerText = userData.cnh || 'Adicionar';
            document.getElementById('pdAntt').innerText = userData.antt || 'Adicionar';
        } else {
            document.getElementById('pdExtraBlock').style.display = 'none';
        }
    }
if (document.getElementById('profEmail')) document.getElementById('profEmail').value = userData.email || '';
    if (document.getElementById('profPhone')) document.getElementById('profPhone').value = userData.telefone || '';
    if (document.getElementById('profAddress')) document.getElementById('profAddress').value = userData.endereco || '';

    // Estrelas (Rating)
    if (document.getElementById('profileRating')) {
        const rating = userData.rating !== undefined ? Number(userData.rating).toFixed(1) : '5.0';
        document.getElementById('profileRating').innerText = rating;
    }

    // Entregas enviadas / concluÃ­das
    if (document.getElementById('profileDeliveries')) {
        const deliveries = userData.entregas !== undefined ? userData.entregas : 0;
        document.getElementById('profileDeliveries').innerText = deliveries;
    }
    
    if (document.getElementById('profileDeliveriesLabel')) {
        document.getElementById('profileDeliveriesLabel').innerText = userData.role === 'shipper' ? 'Enviadas' : 'ConcluÃ­das';
    }
    if (userData.role === 'shipper') {
        const companyName = userData.razao || userData.nome || 'Distribuidora XPTO';
        if (document.getElementById('shipperCompanyName')) {
            document.getElementById('shipperCompanyName').innerText = companyName;
        }
        if (document.getElementById('shipperAvatarInitials')) {
            if (userData.foto) {
                document.getElementById('shipperAvatarInitials').style.backgroundImage = `url('${userData.foto}')`;
                document.getElementById('shipperAvatarInitials').style.backgroundSize = 'cover';
                document.getElementById('shipperAvatarInitials').style.backgroundPosition = 'center';
                document.getElementById('shipperAvatarInitials').innerText = '';
            } else {
                document.getElementById('shipperAvatarInitials').style.backgroundImage = 'none';
                document.getElementById('shipperAvatarInitials').innerText = companyName.substring(0, 2).toUpperCase();
            }
        }
    }

    if (userData.role === 'driver') {
        if (userData.veiculo) {
            if (document.getElementById('profVehicleGroup')) document.getElementById('profVehicleGroup').style.display = 'flex';
            if (document.getElementById('profVehicle')) document.getElementById('profVehicle').value = userData.veiculo;
        } else {
            if (document.getElementById('profVehicleGroup')) document.getElementById('profVehicleGroup').style.display = 'none';
        }
        
        if (document.getElementById('profAnttGroup')) document.getElementById('profAnttGroup').style.display = 'flex';
        if (document.getElementById('profAntt')) document.getElementById('profAntt').value = userData.antt || '';
        
        if (document.getElementById('profCnhNumGroup')) document.getElementById('profCnhNumGroup').style.display = 'flex';
        if (document.getElementById('profCnhNum')) document.getElementById('profCnhNum').value = userData.cnh || '';
        
        if (document.getElementById('profPlacaGroup')) document.getElementById('profPlacaGroup').style.display = 'flex';
        if (document.getElementById('profPlaca')) document.getElementById('profPlaca').value = userData.placa || '';
        
        // Show driver upload options
        if (document.getElementById('upCRLV')) document.getElementById('upCRLV').style.display = 'flex';
        if (document.getElementById('upCPF')) document.getElementById('upCPF').style.display = 'flex';
        if (document.getElementById('upCNH')) document.getElementById('upCNH').style.display = 'flex';
    } else {
        if (document.getElementById('profVehicleGroup')) document.getElementById('profVehicleGroup').style.display = 'none';
        if (document.getElementById('profAnttGroup')) document.getElementById('profAnttGroup').style.display = 'none';
        if (document.getElementById('profCnhNumGroup')) document.getElementById('profCnhNumGroup').style.display = 'none';
        if (document.getElementById('profPlacaGroup')) document.getElementById('profPlacaGroup').style.display = 'none';
        
        // Hide driver upload options (Shippers only need Comprovante Residencia and CNPJ/CPF which is handled below)
        if (document.getElementById('upCRLV')) document.getElementById('upCRLV').style.display = 'none';
        if (document.getElementById('upCNH')) document.getElementById('upCNH').style.display = 'none';
        // upCPF is used as CartÃ£o CNPJ for shippers (see previous implementation or modify text)
        if (userData.tipoDocumento === 'cnpj') {
            const upCpfTitle = document.querySelector('#upCPF p:first-child');
            if (upCpfTitle) upCpfTitle.innerText = "CartÃ£o CNPJ";
        }
    }

    const avatarUrl = userData.foto || 'https://i.imgur.com/vnYcevV.png';
    if (document.getElementById('profileAvatar')) {
        document.getElementById('profileAvatar').style.backgroundImage = `url('${avatarUrl}')`;
    }
    if (document.getElementById('driverHomeAvatar')) {
        document.getElementById('driverHomeAvatar').style.backgroundImage = `url('${avatarUrl}')`;
    }

    // Atualizar status dos documentos anexados
    const checkUploadStatus = (id, baseKey) => {
        const el = document.getElementById(id);
        if (!el) return;
        
        // Verifica se hÃ¡ pelomenos um arquivo (seja o base, ou o Frente, ou o Verso)
        const hasDoc = userData.documentUrls && (
            userData.documentUrls[baseKey] || 
            userData.documentUrls[baseKey + 'Frente'] || 
            userData.documentUrls[baseKey + 'Verso']
        );
        
        const subtitle = el.querySelector('p:last-child');
        const iconRight = el.querySelector('i.ph-upload-simple') || el.querySelector('i.ph-check-circle') || el.querySelector('i.ph-clock') || el.querySelector('i.ph-warning-circle') || el.querySelector('i.ph-x-circle');
        
        if (hasDoc) {
            el.classList.add('uploaded');
            
            // Pega o status individual: primeiro tenta o exato, depois Frente, depois cai pro global
            const indStatus = (userData.documentStatuses && userData.documentStatuses[baseKey])
                            ? userData.documentStatuses[baseKey]
                            : (userData.documentStatuses && userData.documentStatuses[baseKey + 'Frente'])
                                ? userData.documentStatuses[baseKey + 'Frente']
                                : (userData.docStatus || 'Pendente');
            
            if (indStatus === 'Aprovado') {
                if (subtitle) subtitle.innerText = "Verificado";
                if (iconRight) {
                    iconRight.className = 'ph-fill ph-check-circle';
                    iconRight.style.color = '#10b981'; // green
                }
            } else if (indStatus === 'Reprovado' || indStatus === 'Bloqueado') {
                if (subtitle) subtitle.innerText = "Documento recusado";
                if (iconRight) {
                    iconRight.className = 'ph-fill ph-x-circle';
                    iconRight.style.color = '#ef4444'; // red
                }
            } else {
                if (subtitle) subtitle.innerText = "Em anÃ¡lise";
                if (iconRight) {
                    iconRight.className = 'ph-fill ph-clock';
                    iconRight.style.color = '#d97706'; // yellow/orange
                }
            }
        } else {
            el.classList.remove('uploaded');
            if (subtitle) subtitle.innerText = "Toque para enviar";
            if (iconRight) {
                iconRight.className = 'ph ph-upload-simple';
                iconRight.style.color = 'var(--text-muted)';
            }
        }
    };

    if (userData.role === 'shipper') {
        checkUploadStatus('upCNPJ', 'cnpj');
        checkUploadStatus('upEnderecoEmpresa', 'enderecoEmpresa');
    } else {
        checkUploadStatus('upCRLV', 'crlv');
        checkUploadStatus('upResidencia', 'residencia');
        checkUploadStatus('upCPF', 'cpf');
        checkUploadStatus('upCNH', 'cnh');
    }

    // Update Security Documents menu item
    if (document.getElementById('profileDocsStatusText')) {
        let docsStatusText = "Verificar status dos documentos";
        let showDot = false;
        
        if (userData.docStatus === 'Aprovado') {
            docsStatusText = "Todos os documentos verificados";
        } else if (userData.docStatus === 'Reprovado' || userData.docStatus === 'Bloqueado') {
            docsStatusText = "AÃ§Ã£o necessÃ¡ria: Documento recusado";
            showDot = true;
        } else if (userData.docStatus === 'Pendente' || userData.docStatus === 'Em AnÃ¡lise') {
            docsStatusText = "Documentos em anÃ¡lise";
            showDot = true;
        } else {
            docsStatusText = "Envio de documentos pendente";
            showDot = true;
        }
        
        document.getElementById('profileDocsStatusText').innerText = docsStatusText;
        if (document.getElementById('profileDocsAlertDot')) {
            document.getElementById('profileDocsAlertDot').style.display = showDot ? 'block' : 'none';
        }
    }
}

function openPhotoActionSheet() {
    const sheet = document.getElementById('photoActionSheet');
    if (sheet) {
        sheet.style.display = 'flex';
        sheet.offsetHeight; // force reflow
        sheet.style.opacity = '1';
    }
}

function closePhotoActionSheet() {
    const sheet = document.getElementById('photoActionSheet');
    if (sheet) {
        sheet.style.opacity = '0';
        setTimeout(() => {
            sheet.style.display = 'none';
        }, 300);
    }
}

function compressImageToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(e) {
            const img = new Image();
            img.onload = function() {
                const canvas = document.createElement('canvas');
                const MAX_WIDTH = 150;
                const MAX_HEIGHT = 150;
                let width = img.width;
                let height = img.height;

                if (width > height) {
                    if (width > MAX_WIDTH) {
                        height *= MAX_WIDTH / width;
                        width = MAX_WIDTH;
                    }
                } else {
                    if (height > MAX_HEIGHT) {
                        width *= MAX_HEIGHT / height;
                        height = MAX_HEIGHT;
                    }
                }

                canvas.width = width;
                canvas.height = height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0, width, height);

                // Export to high-quality compressed JPEG (0.75)
                const dataUrl = canvas.toDataURL('image/jpeg', 0.75);
                resolve(dataUrl);
            };
            img.onerror = function() { reject(new Error('Erro ao processar imagem')); };
            img.src = e.target.result;
        };
        reader.onerror = function() { reject(new Error('Erro ao ler arquivo')); };
        reader.readAsDataURL(file);
    });
}

async function handleProfilePhoto(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!['image/jpeg', 'image/png', 'image/webp', 'image/jpg', 'image/gif'].includes(file.type)) {
        showToast('Tipo de arquivo nÃ£o permitido.', 'error');
        return;
    }

    showToast('Processando foto de perfil...', 'info');
    
    try {
        // OtimizaÃ§Ã£o: Para evitar erros de CORS e requisiÃ§Ãµes falhas de Storage no console do navegador,
        // salvamos a imagem comprimida em Base64 diretamente no Firestore do usuÃ¡rio.
        const base64Url = await compressImageToBase64(file);
        await db.collection("users").doc(auth.currentUser.uid).update({ 
            foto: base64Url, 
            updatedAt: firebase.firestore.FieldValue.serverTimestamp() 
        });
        userData.foto = base64Url;
        preencherPerfil();
        showToast('Foto de perfil atualizada com sucesso!');
    } catch (fallbackError) {
        console.error('Profile photo update failed:', fallbackError);
        showToast('Erro ao atualizar foto.', 'error');
    }
}

function logout() {
    const sheet = document.getElementById('logoutConfirmModal');
    if (sheet) {
        sheet.style.display = 'flex';
        sheet.offsetHeight; // force reflow
        sheet.style.opacity = '1';
    }
}

function fecharModalLogout() {
    const sheet = document.getElementById('logoutConfirmModal');
    if (sheet) {
        sheet.style.opacity = '0';
        setTimeout(() => {
            sheet.style.display = 'none';
        }, 300);
    }
}

function abrirModalDeleteAccount() {
    const modal = document.getElementById('deleteAccountConfirmModal');
    if (modal) {
        modal.style.display = 'flex';
        modal.offsetHeight; // force reflow
        modal.style.opacity = '1';
    }
}

function fecharModalDeleteAccount() {
    const modal = document.getElementById('deleteAccountConfirmModal');
    if (modal) {
        modal.style.opacity = '0';
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    }
}

async function confirmDeleteAccount() {
    const btn = document.getElementById('btnConfirmDeleteAccount');
    if (btn) {
        btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Excluindo...`;
        btn.disabled = true;
    }
    try {
        const user = auth.currentUser;
        if (!user) throw new Error("UsuÃ¡rio nÃ£o autenticado");

        // Attempt to delete user doc in Firestore
        await db.collection('users').doc(user.uid).delete();
        
        // Delete auth user
        await user.delete();

        showToast('Sua conta foi excluÃ­da permanentemente.', 'success');
        
        setTimeout(() => {
            window.location.reload();
        }, 1500);

    } catch (error) {
        console.error("Erro ao excluir conta:", error);
        if (btn) {
            btn.innerHTML = `Sim, excluir permanentemente`;
            btn.disabled = false;
        }
        if (error.code === 'auth/requires-recent-login') {
            showToast('Para seguranÃ§a, vocÃª precisa fazer login novamente antes de excluir a conta.', 'error');
            setTimeout(() => {
                auth.signOut().then(() => window.location.reload());
            }, 2500);
        } else {
            showToast('Erro ao excluir conta. Tente novamente mais tarde.', 'error');
        }
    }
}

async function confirmarLogoutExec() {
    const btn = document.getElementById('btnConfirmarLogout');
    if (btn) {
        btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Saindo...`;
        btn.disabled = true;
    }
    try {
        if (typeof freightListenerUnsubscribe === 'function') {
            freightListenerUnsubscribe();
            freightListenerUnsubscribe = null;
        }
        await auth.signOut();
        navHistory = [];
        currentUserRole = null;
        userData = {};
        window.isDriverOnline = false;
        
        showToast('VocÃª saiu da conta com seguranÃ§a.', 'info');
        
        // Timeout to allow the toast to show briefly before reloading
        setTimeout(() => {
            window.location.reload();
        }, 800);
        
    } catch (error) {
        showToast('Erro ao sair.', 'error');
        if (btn) {
            btn.innerHTML = `Sim, Sair`;
            btn.disabled = false;
        }
    }
}

// Controla o modo de ediÃ§Ã£o do perfil
let profileEditMode = false;

function toggleEditProfile() {
    profileEditMode = !profileEditMode;
    const fields = ['profName', 'profRazao', 'profPhone', 'profAddress', 'profAntt', 'profCnhNum', 'profPlaca'];
    const btnEdit = document.getElementById('btnEditProfile');
    const btnSave = document.getElementById('btnSaveProfile');

    if (profileEditMode) {
        // Ativar ediÃ§Ã£o
        fields.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.disabled = false;
                el.style.background = '#fff';
                el.style.color = 'var(--text-main)';
                el.style.cursor = 'text';
                el.style.borderColor = 'var(--orange)';
            }
        });
        btnEdit.innerHTML = '<i class="ph ph-x" style="margin-right: 6px;"></i> Cancelar';
        btnEdit.style.borderColor = '#ef4444';
        btnEdit.style.color = '#ef4444';
        btnSave.style.display = 'block';
        // Foca no primeiro campo
        document.getElementById('profName').focus();
    } else {
        // Desativar ediÃ§Ã£o (cancelar)
        fields.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.disabled = true;
                el.style.background = '#f1f5f9';
                el.style.color = '#64748b';
                el.style.cursor = 'not-allowed';
                el.style.borderColor = 'var(--border)';
            }
        });
        btnEdit.innerHTML = '<i class="ph ph-pencil-simple" style="margin-right: 6px;"></i> Editar';
        btnEdit.style.borderColor = '';
        btnEdit.style.color = '';
        btnSave.style.display = 'none';
        // Restaurar dados originais
        if (userData) {
            if(document.getElementById('profName')) document.getElementById('profName').value = userData.nome || '';
            if(document.getElementById('profRazao')) document.getElementById('profRazao').value = userData.razao || '';
            if(document.getElementById('profPhone')) document.getElementById('profPhone').value = userData.telefone || '';
            if(document.getElementById('profAddress')) document.getElementById('profAddress').value = userData.endereco || '';
            if(document.getElementById('profAntt')) document.getElementById('profAntt').value = userData.antt || '';
            if(document.getElementById('profCnhNum')) document.getElementById('profCnhNum').value = userData.cnh || '';
            if(document.getElementById('profPlaca')) document.getElementById('profPlaca').value = userData.placa || '';
        }
    }
}

async function salvarPerfil(btn) {
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Salvando...`;
    btn.disabled = true;

    try {
        const user = auth.currentUser;
        if (!user) {
            showToast('UsuÃ¡rio nÃ£o autenticado.', 'error');
            logSecurityEvent('UNAUTHENTICATED_ACCESS', 'Tentativa de salvar perfil sem autenticaÃ§Ã£o');
            btn.innerHTML = original;
            btn.disabled = false;
            return;
        }

        // SECURITY: Validate and sanitize input before writing
        const updatedData = {
            nome: sanitizeInput(document.getElementById('profName').value.trim(), 200),
            telefone: sanitizeInput(document.getElementById('profPhone').value.trim(), 20),
            endereco: sanitizeInput(document.getElementById('profAddress').value.trim(), 300)
        };
        
        const profRazao = document.getElementById('profRazao');
        if (profRazao && profRazao.value) {
            updatedData.razao = sanitizeInput(profRazao.value.trim(), 200);
        }

        if (userData.role === 'driver') {
            const profAntt = document.getElementById('profAntt');
            if (profAntt) updatedData.antt = sanitizeInput(profAntt.value.trim(), 50);
            
            const profCnhNum = document.getElementById('profCnhNum');
            if (profCnhNum) updatedData.cnh = sanitizeInput(profCnhNum.value.trim(), 50);
            
            const profPlaca = document.getElementById('profPlaca');
            if (profPlaca) updatedData.placa = sanitizeInput(profPlaca.value.trim(), 20);
        }

        // Firestore protegido por Security Rules (sÃ³ permite atualizar campos permitidos)
        updatedData.updatedAt = firebase.firestore.FieldValue.serverTimestamp();
        await db.collection('users').doc(user.uid).update(updatedData);
        Object.assign(userData, updatedData);

        btn.innerHTML = original;
        btn.disabled = false;

        // Volta ao modo bloqueado
        profileEditMode = true; // ForÃ§ar toggle para desligar
        toggleEditProfile();

        showToast('Dados do perfil atualizados com sucesso!');
    } catch (error) {
        btn.innerHTML = original;
        btn.disabled = false;
        showToast(error.message || 'Erro ao salvar perfil.', 'error');
    }
}
// Modal Handle Upload Logic
window.handleUpload = handleUpload;
function handleUpload(elementId, type) {
    let baseKey = '';
    if (elementId === 'upCNH') baseKey = 'cnh';
    else if (elementId === 'upCPF') baseKey = 'cpf';
    else if (elementId === 'upCRLV') baseKey = 'crlv';
    else if (elementId === 'upResidencia') baseKey = 'residencia';
    else if (elementId === 'upCNPJ') baseKey = 'cnpj';
    else if (elementId === 'upEnderecoEmpresa') baseKey = 'enderecoEmpresa';
    else baseKey = elementId;

    const indStatus = (userData.documentStatuses && userData.documentStatuses[baseKey])
                    ? userData.documentStatuses[baseKey]
                    : (userData.documentStatuses && userData.documentStatuses[baseKey + 'Frente'])
                        ? userData.documentStatuses[baseKey + 'Frente']
                        : null;

    if (indStatus === 'Aprovado') {
        showToast('Este documento jÃ¡ foi verificado e aprovado.', 'info');
        return;
    }

    const modal = document.getElementById('documentUploadModal');
    if (!modal) return;
    
    document.getElementById('docUploadTitle').innerText = type;
    
    const isDouble = type === 'CPF' || type === 'CNH';
    
    const singleContainer = document.getElementById('docUploadSingleContainer');
    const doubleContainer = document.getElementById('docUploadDoubleContainer');
    
    document.getElementById('docUploadSingleFile').value = '';
    document.getElementById('docUploadFrenteFile').value = '';
    document.getElementById('docUploadVersoFile').value = '';
    document.getElementById('docUploadSinglePreview').style.display = 'none';
    document.getElementById('docUploadFrentePreview').style.display = 'none';
    document.getElementById('docUploadVersoPreview').style.display = 'none';
    
    if (isDouble) {
        singleContainer.style.display = 'none';
        doubleContainer.style.display = 'flex';
    } else {
        singleContainer.style.display = 'block';
        doubleContainer.style.display = 'none';
    }
    
    window.currentUploadElementId = elementId;
    window.currentUploadType = type;
    window.currentUploadIsDouble = isDouble;
    
    modal.style.display = 'flex';
    modal.offsetHeight; // reflow
    modal.style.opacity = '1';
}

window.previewDocUpload = previewDocUpload;
function previewDocUpload(previewType) {
    let inputId = '';
    let previewId = '';
    if (previewType === 'single') {
        inputId = 'docUploadSingleFile';
        previewId = 'docUploadSinglePreview';
    } else if (previewType === 'frente') {
        inputId = 'docUploadFrenteFile';
        previewId = 'docUploadFrentePreview';
    } else if (previewType === 'verso') {
        inputId = 'docUploadVersoFile';
        previewId = 'docUploadVersoPreview';
    }
    
    const file = document.getElementById(inputId).files[0];
    const preview = document.getElementById(previewId);
    if (file) {
        if (file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = function(e) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            }
            reader.readAsDataURL(file);
        } else {
            preview.style.display = 'none';
        }
    }
}

window.closeDocUploadModal = closeDocUploadModal;
function closeDocUploadModal() {
    const modal = document.getElementById('documentUploadModal');
    if (modal) {
        modal.style.opacity = '0';
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    }
}

window.confirmDocUpload = confirmDocUpload;
async function confirmDocUpload() {
    const isDouble = window.currentUploadIsDouble;
    const btn = document.getElementById('btnConfirmDocUpload');
    
    let files = {};
    if (isDouble) {
        files.frente = document.getElementById('docUploadFrenteFile').files[0];
        files.verso = document.getElementById('docUploadVersoFile').files[0];
        if (!files.frente || !files.verso) {
            showToast('Por favor, selecione as fotos da frente e do verso.', 'error');
            return;
        }
    } else {
        files.single = document.getElementById('docUploadSingleFile').files[0];
        if (!files.single) {
            showToast('Por favor, selecione o arquivo do documento.', 'error');
            return;
        }
    }
    
    const originalText = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Enviando...`;
    btn.disabled = true;
    
    try {
        const uid = auth.currentUser.uid;
        let updates = { docStatus: 'Pendente', updatedAt: firebase.firestore.FieldValue.serverTimestamp() };
        let docUrls = userData.documentUrls || {};
        
        const compressImageToBase64 = (file, maxWidth = 800) => {
            return new Promise((resolve, reject) => {
                if (!file || !file.type.match(/image.*/)) {
                    const reader = new FileReader();
                    reader.onload = e => resolve(e.target.result);
                    reader.onerror = error => reject(error);
                    if(file) reader.readAsDataURL(file); else resolve(null);
                    return;
                }
                const reader = new FileReader();
                reader.onload = function(event) {
                    const img = new Image();
                    img.onload = function() {
                        const canvas = document.createElement('canvas');
                        let width = img.width;
                        let height = img.height;
                        if (width > maxWidth) {
                            height = Math.round(height * maxWidth / width);
                            width = maxWidth;
                        }
                        canvas.width = width;
                        canvas.height = height;
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(img, 0, 0, width, height);
                        resolve(canvas.toDataURL('image/jpeg', 0.6));
                    };
                    img.onerror = error => reject(error);
                    img.src = event.target.result;
                };
                reader.readAsDataURL(file);
            });
        };
        
        let baseKey = '';
        if (window.currentUploadElementId === 'upCNH') baseKey = 'cnh';
        else if (window.currentUploadElementId === 'upCPF') baseKey = 'cpf';
        else if (window.currentUploadElementId === 'upCRLV') baseKey = 'crlv';
        else if (window.currentUploadElementId === 'upResidencia') baseKey = 'residencia';
        else if (window.currentUploadElementId === 'upCNPJ') baseKey = 'cnpj';
        else if (window.currentUploadElementId === 'upEnderecoEmpresa') baseKey = 'enderecoEmpresa';
        else baseKey = window.currentUploadElementId;

        if (isDouble) {
            docUrls[baseKey + 'Frente'] = await compressImageToBase64(files.frente);
            docUrls[baseKey + 'Verso'] = await compressImageToBase64(files.verso);
        } else {
            docUrls[baseKey] = await compressImageToBase64(files.single);
        }
        
        updates.documentUrls = docUrls;

        // Ao reenviar um documento, redefinir seu status individual para Pendente
        let documentStatuses = userData.documentStatuses || {};
        documentStatuses[baseKey] = 'Pendente';
        if (isDouble) {
            documentStatuses[baseKey + 'Frente'] = 'Pendente';
            documentStatuses[baseKey + 'Verso'] = 'Pendente';
        }
        updates.documentStatuses = documentStatuses;

        await db.collection("users").doc(uid).update(updates);
        
        userData.docStatus = 'Pendente';
        userData.documentUrls = docUrls;
        userData.documentStatuses = documentStatuses;
        
        // Update UI locally
        const el = document.getElementById(window.currentUploadElementId);
        if (el) {
            el.classList.add('uploaded');
            const subtitle = el.querySelector('div > div > p:last-child');
            if (subtitle) subtitle.innerText = "Em anÃ¡lise";
            const iconRight = el.querySelector('i.ph-upload-simple') || el.querySelector('i.ph-check-circle') || el.querySelector('i.ph-warning-circle') || el.querySelector('i.ph-x-circle');
            if (iconRight) {
                iconRight.className = 'ph-fill ph-clock';
                iconRight.style.color = '#d97706';
            }
        }
        
        preencherPerfil(); // update badges
        showToast('Documento enviado com sucesso!');
        closeDocUploadModal();
        
    } catch (err) {
        console.error("Erro no upload", err);
        showToast('Erro ao enviar documento. Tente novamente.', 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function salvarCadastroMotorista(btn) {
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Criando conta...`;
    setTimeout(() => {
        btn.innerHTML = original;
        showToast('Cadastro realizado com sucesso! Bem-vindo ao PegaFrete.');
        setRole('driver');
    }, 1500);
}

function solicitarSaque(btn) {
    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Processando PIX...`;
    setTimeout(() => {
        btn.innerHTML = original;
        showToast('TransferÃªncia enviada. O valor cairÃ¡ na sua conta em instantes.');
    }, 2000);
}

window.isDriverOnline = false;
function toggleStatus(btn) {
    if (userData && userData.role === 'driver' && userData.docStatus !== 'Aprovado') {
        showToast('Sua documentaÃ§Ã£o precisa ser aprovada para vocÃª ficar online.', 'error');
        return;
    }

    const box = document.getElementById('driverStatusBox');
    const indicator = document.getElementById('driverStatusIndicator');
    if (!box || !indicator) return;

    if (btn.innerText.trim() === 'Ficar Online') {
        window.isDriverOnline = true;
        btn.innerText = 'Pausar';
        box.classList.remove('offline');
        box.classList.add('online');
        renderFretes();

        indicator.innerHTML = `
            <span class="status-indicator-dot"></span>
            <span class="status-indicator-text">DisponÃ­vel para cargas</span>
        `;
        showToast('VocÃª estÃ¡ online e visÃ­vel para novas cargas!');
    } else {
        window.isDriverOnline = false;
        btn.innerText = 'Ficar Online';
        box.classList.remove('online');
        box.classList.add('offline');
        renderFretes();

        indicator.innerHTML = `
            <span class="status-indicator-dot"></span>
            <span class="status-indicator-text">Oculto no Radar</span>
        `;
        showToast('VocÃª agora estÃ¡ invisÃ­vel no radar.', 'info');
    }
}


function aceitarFrete(btn) {
    const originalText = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Reservando carga...`;

    setTimeout(() => {
        btn.innerHTML = `<i class="ph-fill ph-check-circle"></i> Viagem Iniciada!`;
        btn.style.background = '#22c55e';
        showToast('Carga confirmada! Acompanhe os detalhes na Ã¡rea de Chat.');
    }, 1500);
}

function formatTimeAgo(timestamp) {
    if (!timestamp) return 'Agora';
    let date;
    if (timestamp.toDate) {
        date = timestamp.toDate();
    } else {
        date = new Date(timestamp);
    }
    
    const now = new Date();
    const diffMs = now - date;
    if (isNaN(diffMs) || diffMs < 0) return 'Agora';

    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    const diffWeeks = Math.floor(diffDays / 7);

    if (diffMins < 60) return 'Publicada agora';
    if (diffHours < 24) return 'Hoje';
    if (diffDays < 7) {
        return diffDays === 1 ? 'a 1 dia' : `a ${diffDays} dias`;
    }
    if (diffWeeks < 52) {
        return diffWeeks === 1 ? 'a 1 semana' : `a ${diffWeeks} semanas`;
    }
    return 'a mais de 1 ano';
}

function renderFretes() {
    const areaHome = document.getElementById('dynamicFreights');
    const areaSearch = document.getElementById('dynamicFreightsSearch');
    const areaShipper = document.getElementById('shipperActiveFreights');

    // Filtragem de cargas
    let listFretesHome = fretes;
    let listFretesSearch = fretes;

    if (userData) {
        if (userData.role === 'shipper') {
            listFretesHome = fretes.filter(f => f.shipperUid === auth.currentUser?.uid && f.status !== 'entregue' && f.status !== 'cancelado');
            listFretesSearch = listFretesHome;
        } else if (userData.role === 'driver') {
            if (!window.isDriverOnline) {
                listFretesHome = [];
                listFretesSearch = [];
            } else {
                listFretesHome = fretes.filter(f => f.status !== 'entregue' && f.status !== 'cancelado');
                if (userData.veiculo) {
                    listFretesHome = listFretesHome.filter(f => f.veiculo && f.veiculo.toLowerCase() === userData.veiculo.toLowerCase());
                }
                listFretesSearch = listFretesHome;
            }
        }
    }

    let htmlHome = '';
    let htmlSearch = '';

    // Render Home Feed
    if (listFretesHome.length === 0) {
        htmlHome = `
            <div class="empty-feed-card">
                <div class="empty-icon-circle">
                    <i class="ph ph-warning-circle"></i>
                </div>
                <h3>Sem cargas compatÃ­veis</h3>
                <p>Não encontramos nenhuma carga publicada compatÃ­vel com seu veÃ­culo no momento.</p>
            </div>
        `;
    } else {
        listFretesHome.forEach((frete) => {
            const idParam = typeof frete.id === 'string' ? `'${frete.id}'` : frete.id;
            let shipperActions = '';
            if (userData && userData.role === 'shipper' && frete.status !== 'entregue' && frete.status !== 'cancelado') {
                shipperActions = `
                    <div style="display: flex; gap: 8px; margin-top: 12px; width: 100%;">
                        <button class="btn btn-primary" style="flex: 1; padding: 10px; font-size: 13px; background: #22c55e;" onclick="event.stopPropagation(); concluirFrete(${idParam})">
                            <i class="ph ph-check-circle"></i> Concluir
                        </button>
                        <button class="btn btn-outline" style="flex: 1; padding: 10px; font-size: 13px; color: #ef4444; border-color: #ef4444;" onclick="event.stopPropagation(); cancelarFrete(${idParam})">
                            <i class="ph ph-x-circle"></i> Cancelar
                        </button>
                    </div>
                `;
            }
            htmlHome += `
              <div class="premium-freight-card" onclick="openFreight(${idParam})">
                  <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                      <span class="time-ago-badge" style="font-size: 11px; color: var(--text-muted); font-weight: 600; display: flex; align-items: center; gap: 4px;">
                          <i class="ph ph-clock"></i> ${formatTimeAgo(frete.createdAt)}
                      </span>
                      <div style="display: flex; gap: 8px; font-size: 11px; color: var(--text-muted); font-weight: 600;">
                          ${frete.distanciaKm ? `<span style="display: flex; align-items: center; gap: 4px;"><i class="ph ph-map-pin"></i> ~${sanitizeHTML(String(frete.distanciaKm))} km</span>` : ''}
                          ${frete.duracaoDias ? `<span style="display: flex; align-items: center; gap: 4px;"><i class="ph ph-calendar"></i> ~${sanitizeHTML(String(frete.duracaoDias))} dia(s)</span>` : ''}
                      </div>
                  </div>
                  <div class="card-route-section">
                      <div class="route-city-block">
                          <span class="route-label">Origem</span>
                          <span class="city-name">${sanitizeHTML(frete.origem)}</span>
                      </div>
                      <div class="route-connector">
                          <i class="ph ph-arrow-right"></i>
                      </div>
                      <div class="route-city-block">
                          <span class="route-label">Destino</span>
                          <span class="city-name">${sanitizeHTML(frete.destino)}</span>
                      </div>
                  </div>
                  <div class="card-details-section">
                      <div class="card-badges">
                          <span class="badge badge-type"><i class="ph ph-package"></i> ${sanitizeHTML(frete.tipo)}</span>
                          <span class="badge badge-vehicle"><i class="ph ph-truck"></i> ${sanitizeHTML(frete.veiculo)}</span>
                      </div>
                      <div class="card-price-block">
                          <span class="price-label">Valor do Frete</span>
                          <span class="price-value">R$ ${sanitizeHTML(frete.valor)}</span>
                      </div>
                  </div>
                  <div class="card-action-bar" style="flex-direction: column;">
                      <button class="btn-apply" onclick="event.stopPropagation(); openFreight(${idParam})">
                          Visualizar <i class="ph ph-arrow-right"></i>
                      </button>
                      ${shipperActions}
                  </div>
              </div>
            `;
        });
    }

    // Render Search Feed
    if (listFretesSearch.length === 0) {
        htmlSearch = `
            <div class="empty-feed-card">
                <div class="empty-icon-circle">
                    <i class="ph ph-warning-circle"></i>
                </div>
                <h3>Nenhuma carga disponÃ­vel</h3>
                <p>Não hÃ¡ nenhuma publicaÃ§Ã£o de carga ativa no momento.</p>
            </div>
        `;
    } else {
        listFretesSearch.forEach((frete) => {
            const idParam = typeof frete.id === 'string' ? `'${frete.id}'` : frete.id;
            htmlSearch += `
              <div class="premium-freight-card" onclick="openFreight(${idParam})">
                  <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                      <span class="time-ago-badge" style="font-size: 11px; color: var(--text-muted); font-weight: 600; display: flex; align-items: center; gap: 4px;">
                          <i class="ph ph-clock"></i> ${formatTimeAgo(frete.createdAt)}
                      </span>
                      <div style="display: flex; gap: 8px; font-size: 11px; color: var(--text-muted); font-weight: 600;">
                          ${frete.distanciaKm ? `<span style="display: flex; align-items: center; gap: 4px;"><i class="ph ph-map-pin"></i> ~${sanitizeHTML(String(frete.distanciaKm))} km</span>` : ''}
                          ${frete.duracaoDias ? `<span style="display: flex; align-items: center; gap: 4px;"><i class="ph ph-calendar"></i> ~${sanitizeHTML(String(frete.duracaoDias))} dia(s)</span>` : ''}
                      </div>
                  </div>
                  <div class="card-route-section">
                      <div class="route-city-block">
                          <span class="route-label">Origem</span>
                          <span class="city-name">${sanitizeHTML(frete.origem)}</span>
                      </div>
                      <div class="route-connector">
                          <i class="ph ph-arrow-right"></i>
                      </div>
                      <div class="route-city-block">
                          <span class="route-label">Destino</span>
                          <span class="city-name">${sanitizeHTML(frete.destino)}</span>
                      </div>
                  </div>
                  <div class="card-details-section">
                      <div class="card-badges">
                          <span class="badge badge-type"><i class="ph ph-package"></i> ${sanitizeHTML(frete.tipo)}</span>
                          <span class="badge badge-vehicle"><i class="ph ph-truck"></i> ${sanitizeHTML(frete.veiculo)}</span>
                      </div>
                      <div class="card-price-block">
                          <span class="price-label">Valor do Frete</span>
                          <span class="price-value">R$ ${sanitizeHTML(frete.valor)}</span>
                      </div>
                  </div>
                  <div class="card-action-bar">
                      <button class="btn-apply" onclick="event.stopPropagation(); openFreight(${idParam})">
                          Visualizar e Candidatar <i class="ph ph-arrow-right"></i>
                      </button>
                  </div>
              </div>
            `;
        });
    }

    if (areaHome) areaHome.innerHTML = htmlHome;
    if (areaSearch) areaSearch.innerHTML = htmlSearch;

    // Render para o painel do Embarcador (com botÃ£o editar)
    if (areaShipper) {
        let shipperHtml = '';
        listFretesHome.forEach(f => {
            const statusLabel = f.status === 'transito' ? '<i class="ph ph-navigation-arrow"></i> Em trÃ¢nsito' : '<i class="ph ph-hourglass"></i> Aguardando motorista';
            const statusClass = f.status === 'transito' ? 'status-transito' : 'status-pendente';
            const safeId = typeof f.id === 'string' ? `'${sanitizeHTML(f.id)}'` : f.id;

            let shipperActions = '';
            if (f.status !== 'entregue' && f.status !== 'cancelado') {
                shipperActions = `
                    <div style="display: flex; gap: 8px; margin-top: 12px; width: 100%;">
                        <button class="btn btn-primary" style="flex: 1; padding: 10px; font-size: 13px; background: #22c55e;" onclick="event.stopPropagation(); concluirFrete(${safeId})">
                            <i class="ph ph-check-circle"></i> Concluir
                        </button>
                        <button class="btn btn-outline" style="flex: 1; padding: 10px; font-size: 13px; color: #ef4444; border-color: #ef4444;" onclick="event.stopPropagation(); cancelarFrete(${safeId})">
                            <i class="ph ph-x-circle"></i> Cancelar
                        </button>
                    </div>
                `;
            }

            shipperHtml += `
                    <div class="premium-freight-card shipper-card">
                      <div class="card-header-shipper">
                          <span class="status-badge ${statusClass}">${statusLabel}</span>
                          <button class="btn-edit-freight" onclick="abrirEdicaoFrete(${safeId})">
                              <i class="ph ph-pencil-simple"></i> Editar Carga
                          </button>
                      </div>
                      <div class="card-route-section">
                          <div class="route-city-block">
                              <span class="route-label">Origem</span>
                              <span class="city-name">${sanitizeHTML(f.origem)}</span>
                          </div>
                          <div class="route-connector">
                              <i class="ph ph-arrow-right"></i>
                          </div>
                          <div class="route-city-block">
                              <span class="route-label">Destino</span>
                              <span class="city-name">${sanitizeHTML(f.destino)}</span>
                          </div>
                      </div>
                      <div class="card-details-section">
                          <div class="card-badges">
                              <span class="badge badge-type"><i class="ph ph-package"></i> ${sanitizeHTML(f.tipo)}</span>
                              <span class="badge badge-vehicle"><i class="ph ph-truck"></i> ${sanitizeHTML(f.veiculo)}</span>
                          </div>
                          <div class="card-price-block">
                              <span class="price-label">Valor do Frete</span>
                              <span class="price-value">R$ ${sanitizeHTML(f.valor)}</span>
                          </div>
                      </div>
                      ${shipperActions}
                    </div>
                `;
        });
        areaShipper.innerHTML = shipperHtml || htmlHome;
    }

    buscarFretes();

    // Atualiza tambÃ©m o histÃ³rico do Embarcador
    renderShipperHistory();
}

function openFreight(idOrIndex) {
    let frete;
    if (typeof idOrIndex === 'number') {
        frete = fretes[idOrIndex];
    } else {
        frete = fretes.find(f => f.id === idOrIndex);
    }
    if (!frete) return;
    window.currentFreight = frete;
    document.getElementById('detailRoute').innerHTML = `${sanitizeHTML(frete.origem)} <i class="ph ph-arrow-right route-arrow"></i> ${sanitizeHTML(frete.destino)}`;
    document.getElementById('detailOriginText').innerText = frete.origem;
    document.getElementById('detailDestinationText').innerText = frete.destino;
    document.getElementById('detailPaymentText').innerText = `R$ ${frete.valor}`;
    document.getElementById('detailObsText').innerText = frete.obs || 'Nenhuma observaÃ§Ã£o informada.';

    // Formatar datas no formato brasileiro (DD/MM/AAAA)
    const formatDateBR = (dateStr) => {
        if (!dateStr) return '--';
        const parts = dateStr.split('-');
        if (parts.length === 3) {
            return `${parts[2]}/${parts[1]}/${parts[0]}`;
        }
        return dateStr;
    };

    // Preenche as novas informaÃ§Ãµes de detalhes da carga
    document.getElementById('detailColetaText').innerText = formatDateBR(frete.coleta);
    document.getElementById('detailPrevisaoText').innerText = formatDateBR(frete.previsao);
    document.getElementById('detailPesoText').innerText = frete.peso ? `${frete.peso} kg` : '--';
    
    if (frete.volume) {
        document.getElementById('detailVolumeRow').style.display = 'flex';
        document.getElementById('detailVolumeText').innerText = `${frete.volume} mÂ³`;
    } else {
        document.getElementById('detailVolumeRow').style.display = 'none';
    }

    const distKm = frete.distanciaKm || frete.distancia || 0;
    document.getElementById('detailDistanciaText').innerText = distKm ? `~${distKm} km` : 'Calculando...';
    document.getElementById('detailUrgenciaText').innerText = frete.urgencia || 'Normal';

    // Badge de urgÃªncia dinÃ¢mica com cores
    const badges = document.getElementById('detailBadges');
    let urgencyBadgeColor = '#64748b';
    let urgencyBadgeBg = '#f1f5f9';
    if (frete.urgencia === 'Alta') {
        urgencyBadgeColor = '#ef4444';
        urgencyBadgeBg = '#fef2f2';
    } else if (frete.urgencia === 'MÃ©dia') {
        urgencyBadgeColor = '#f97316';
        urgencyBadgeBg = '#fff7ed';
    }

    badges.innerHTML = `
        <div class="tag blue"><i class="ph ph-package"></i> ${sanitizeHTML(frete.tipo)}</div>
        <div class="tag orange"><i class="ph ph-truck"></i> ${sanitizeHTML(frete.veiculo)}</div>
        <div class="tag" style="background: ${urgencyBadgeBg}; color: ${urgencyBadgeColor};">
            <i class="ph ph-clock"></i> ${sanitizeHTML(frete.urgencia || 'Normal')}
        </div>
    `;

    const btnCall = document.getElementById('btnCall');
    const btnWhatsApp = document.getElementById('btnWhatsApp');
    
    if (userData && userData.role === 'driver' && userData.docStatus !== 'Aprovado') {
        const blockMsg = "showToast('Sua documentaÃ§Ã£o precisa ser aprovada para negociar cargas.', 'error');";
        btnCall.setAttribute('onclick', blockMsg);
        btnCall.style.opacity = '0.5';
        btnWhatsApp.setAttribute('onclick', blockMsg);
        btnWhatsApp.style.opacity = '0.5';
    } else {
        btnCall.setAttribute('onclick', `window.open('tel:${frete.telefoneContato}', '_blank')`);
        btnCall.style.opacity = '1';
        btnWhatsApp.setAttribute('onclick', `window.open('https://wa.me/55${frete.whatsappContato.replace(/\\D/g, '')}?text=${encodeURIComponent('OlÃ¡, vim pelo PegaFrete. Tenho interesse na carga de ' + frete.origem + ' para ' + frete.destino + '.')}', '_blank')`);
        btnWhatsApp.style.opacity = '1';
    }

    navTo('freightDetails');

    // Inicializa ou atualiza o Mapa de Detalhes da Carga
    setTimeout(async () => {
        const mapContainer = document.getElementById('detailLeafletMap');
        if (!mapContainer) return;

        if (window.detailMap) {
            window.detailMap.remove();
        }

        window.detailMap = L.map('detailLeafletMap', {
            zoomControl: false,
            dragging: false,
            touchZoom: false,
            scrollWheelZoom: false,
            doubleClickZoom: false
        }).setView([-14.235, -51.925], 4);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: 'Â© OpenStreetMap'
        }).addTo(window.detailMap);

        if (typeof obterCoordenadasNominatim === 'function') {
            const p1 = await obterCoordenadasNominatim(frete.origem);
            const p2 = await obterCoordenadasNominatim(frete.destino);

            if (p1 && p2) {
                const originMarker = L.marker([p1.lat, p1.lon]).addTo(window.detailMap);
                const destinationMarker = L.marker([p2.lat, p2.lon]).addTo(window.detailMap);

                L.polyline([[p1.lat, p1.lon], [p2.lat, p2.lon]], {
                    color: '#f97316',
                    weight: 4,
                    opacity: 0.8,
                    dashArray: '5, 10'
                }).addTo(window.detailMap);

                const group = new L.featureGroup([originMarker, destinationMarker]);
                window.detailMap.fitBounds(group.getBounds().pad(0.2));
            }
        }
    }, 300);
}

function buscarFretes() {
    const termo = document.getElementById('searchFrete').value.toLowerCase();
    const cards = document.querySelectorAll('#dynamicFreightsSearch .freight-card');

    cards.forEach(card => {
        const texto = card.innerText.toLowerCase();
        if (texto.includes(termo)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

async function publicarFrete(btn) {
    const originalContent = btn.innerHTML;

    const origem = document.getElementById('origem').value.trim();
    const destino = document.getElementById('destino').value.trim();
    const tipo = document.getElementById('tipoCarga').value;
    const veiculo = document.getElementById('veiculo').value;
    const valor = document.getElementById('valorFrete').value.trim();
    const obs = document.getElementById('obsCarga').value.trim();
    const telefoneContato = document.getElementById('telefoneContato').value.trim();
    const whatsappContato = document.getElementById('whatsappContato').value.trim();
    // Novas variaveis
    const peso = document.getElementById('pesoCarga')?.value.trim() || '';
    const volume = document.getElementById('volumeCarga')?.value.trim() || '';
    const coleta = document.getElementById('coletaCarga')?.value.trim() || '';
    const previsao = document.getElementById('previsaoCarga')?.value.trim() || '';
    const urgencia = document.getElementById('urgenciaCarga')?.value || 'Normal';


    // Client-side validation (also validated server-side)
    if (!origem || !destino || !valor || !tipo || !veiculo || !telefoneContato || !whatsappContato || !peso) {
        showToast('Preencha todas as informaÃ§Ãµes obrigatÃ³rias (incluindo o peso estimado e contatos) para publicar.', 'error');
        return;
    }

    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Publicando...`;
    btn.disabled = true;

    try {
        // Whitelist validation
        if (!VALID_TIPOS.includes(tipo) || !VALID_VEICULOS.includes(veiculo)) {
            showToast('Tipo de carga ou veÃ­culo invÃ¡lido.', 'error');
            logSecurityEvent('INVALID_INPUT', `Tentativa de publicar carga com veÃ­culo/tipo invÃ¡lido: ${tipo} / ${veiculo}`);
            btn.innerHTML = originalContent;
            btn.disabled = false;
            return;
        }

        // Obter coordenadas para calcular distÃ¢ncia
        let distanciaKm = 0;
        let duracaoDias = 0;

        if (typeof obterCoordenadasNominatim === 'function') {
            const p1 = await obterCoordenadasNominatim(origem);
            const p2 = await obterCoordenadasNominatim(destino);
            if (p1 && p2) {
                // Formula de Haversine
                const R = 6371;
                const dLat = (p2.lat - p1.lat) * Math.PI / 180;
                const dLon = (p2.lon - p1.lon) * Math.PI / 180;
                const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                        Math.cos(p1.lat * Math.PI / 180) * Math.cos(p2.lat * Math.PI / 180) *
                        Math.sin(dLon/2) * Math.sin(dLon/2);
                const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
                const straightDist = R * c;
                
                distanciaKm = Math.round(straightDist * 1.3); // 30% a mais para vias reais
                duracaoDias = Math.max(1, Math.ceil(distanciaKm / 500)); // ~500 km/dia
            }
        }

        // Firestore protegido por Security Rules (valida role, ownership e campos)
        const novoFrete = {
            origem: sanitizeInput(origem, 200),
            destino: sanitizeInput(destino, 200),
            valor: sanitizeInput(valor.replace('R$ ', ''), 20),
            tipo,
            veiculo,
            telefoneContato: sanitizeInput(telefoneContato, 20),
            whatsappContato: sanitizeInput(whatsappContato, 20),
            status: 'pendente',
            obs: sanitizeInput(obs, 500) || 'Carga publicada via radar.',
            peso: sanitizeInput(peso, 50),
            volume: sanitizeInput(volume, 50),
            coleta: sanitizeInput(coleta, 50),
            previsao: sanitizeInput(previsao, 50),
            urgencia: sanitizeInput(urgencia, 50),
            distancia: distanciaKm ? distanciaKm : 0,
            shipperUid: auth.currentUser.uid,
            createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            distanciaKm,
            duracaoDias
        };

        await db.collection('freights').add(novoFrete);

        showToast('Carga publicada com sucesso! Divulgada em tempo real para os motoristas.');

        // Limpa campos e reseta steps
        resetPublishStep();
        if(document.getElementById('pesoCarga')) document.getElementById('pesoCarga').value = '';
        if(document.getElementById('volumeCarga')) document.getElementById('volumeCarga').value = '';
        if(document.getElementById('coletaCarga')) document.getElementById('coletaCarga').value = '';
        if(document.getElementById('previsaoCarga')) document.getElementById('previsaoCarga').value = '';
        if(document.getElementById('urgenciaCarga')) document.getElementById('urgenciaCarga').value = 'Normal';

        btn.innerHTML = originalContent;
        btn.disabled = false;
        navTo('shipper');
    } catch (error) {
        btn.innerHTML = originalContent;
        btn.disabled = false;
        showToast(error.message || 'Erro ao publicar carga.', 'error');
    }
}

function renderChats() {
    renderSystemMessages();
}

function enviarMensagem() {
    const input = document.getElementById('newMessage');
    const text = input.value.trim();
    if (!text) return;

    if (window.activeChatName === 'Pega Frete') {
        const uid = auth.currentUser?.uid;
        if (!uid) return;
        
        input.value = '';
        input.style.height = 'auto';
        
        db.collection("system_messages").add({
            userUid: uid,
            text: text,
            sender: 'VocÃª',
            isMe: true,
            read: true,
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
        }).catch(err => {
            console.error("Erro ao enviar mensagem:", err);
            showToast("Erro ao enviar mensagem.", "error");
        });
    } else {
        const now = new Date();
        const time = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
        mensagens.push({ isMe: true, sender: 'VocÃª', text: text, time: time });
        input.value = '';
        input.style.height = 'auto';
        renderChats();
    }
}

function openChatDetail(name, status, avatar, phone = '') {
    window.activeChatName = name;
    document.getElementById('activeChatName').textContent = name;
    
    const phoneLink = document.getElementById('chatPhoneLink');
    if (phoneLink) {
        if (phone) {
            phoneLink.href = 'tel:' + phone;
            phoneLink.style.display = 'flex';
        } else {
            phoneLink.style.display = 'none';
        }
    }
    
    // Hide footer (input area) and menu button (three vertical dots) for administrative channel
    const chatFooter = document.getElementById('chatFooter');
    const chatMenuBtn = document.getElementById('chatMenuBtn');
    if (name === 'Pega Frete') {
        if (chatFooter) chatFooter.style.display = 'none';
        if (chatMenuBtn) chatMenuBtn.style.display = 'none';
    } else {
        if (chatFooter) chatFooter.style.display = 'block';
        if (chatMenuBtn) chatMenuBtn.style.display = 'flex';
    }
    
    document.getElementById('activeChatStatusText').textContent = status;
    
    const avatarImg = document.getElementById('activeChatAvatar');
    if (avatarImg) {
        if (name === 'Pega Frete') {
            avatarImg.src = '/orange_truck_avatar.png';
        } else {
            avatarImg.src = avatar;
        }
    }
    
    if (status === 'Online') {
        document.getElementById('activeChatStatusDot').style.display = 'block';
    } else {
        document.getElementById('activeChatStatusDot').style.display = 'none';
    }
    
    if (name === 'Pega Frete') {
        renderSystemMessages();
        marcarMensagensComoLidas();
    } else {
        renderChats();
    }
    
    navTo('chat_detail');
}

function startSystemMessagesListener() {
    if (systemMessagesListener) {
        systemMessagesListener();
    }
    
    const uid = auth.currentUser?.uid;
    if (!uid) return;
    
    const ref = db.collection("system_messages")
        .where("userUid", "==", uid);
        
    systemMessagesListener = ref.onSnapshot(snapshot => {
        systemMessages = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            systemMessages.push({
                id: doc.id,
                ...data
            });
        });
        
        // Client-side sort to avoid composite index requirement
        systemMessages.sort((a, b) => {
            const timeA = a.createdAt ? (typeof a.createdAt.toMillis === 'function' ? a.createdAt.toMillis() : 0) : 0;
            const timeB = b.createdAt ? (typeof b.createdAt.toMillis === 'function' ? b.createdAt.toMillis() : 0) : 0;
            return timeA - timeB;
        });
        
        if (systemMessages.length === 0) {
            db.collection("system_messages").add({
                userUid: uid,
                text: "Bem-vindo ao canal oficial do Pega Frete! Aqui vocÃª receberÃ¡ avisos importantes, atualizaÃ§Ãµes do aplicativo e notificaÃ§Ãµes sobre suas cargas.",
                sender: "Pega Frete",
                isMe: false,
                read: false,
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
            });
            return;
        }
        
        updateChatListUI();
        
        const chatDetailScreen = document.getElementById('chat_detail');
        if (chatDetailScreen && chatDetailScreen.classList.contains('active') && window.activeChatName === 'Pega Frete') {
            renderSystemMessages();
            marcarMensagensComoLidas();
        }
    }, err => {
        console.error("Erro no listener de mensagens do sistema:", err);
    });
}

function updateChatListUI() {
    const unreadCount = systemMessages.filter(m => !m.isMe && !m.read).length;
    
    // Atualiza o badge da barra de navegaÃ§Ã£o inferior
    const bottomNavBadge = document.querySelector('#bottomNav .notification-badge');
    if (bottomNavBadge) {
        if (unreadCount > 0) {
            bottomNavBadge.textContent = unreadCount > 99 ? '99+' : unreadCount;
            bottomNavBadge.style.display = 'flex';
        } else {
            bottomNavBadge.style.display = 'none';
        }
    }

    if (systemMessages.length === 0) return;
    
    const lastMsg = systemMessages[systemMessages.length - 1];
    
    const previewEl = document.getElementById('systemChatPreview');
    if (previewEl) {
        const textToPreview = lastMsg.text || lastMsg.message || lastMsg.title || '';
        previewEl.innerHTML = (lastMsg.isMe ? '<i class="ph-fill ph-check-circle" style="color: #3b82f6; margin-right: 4px; font-size: 16px;"></i>' : '') + sanitizeHTML(textToPreview);
    }
    
    const timeEl = document.getElementById('systemChatTime');
    if (timeEl) {
        let timeStr = '--:--';
        if (lastMsg.createdAt) {
            const date = lastMsg.createdAt.toDate ? lastMsg.createdAt.toDate() : new Date();
            timeStr = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
        }
        timeEl.textContent = timeStr;
    }
    
    const badgeEl = document.getElementById('systemChatUnreadBadge');
    const itemEl = document.getElementById('systemChatItem');
    
    if (badgeEl) {
        if (unreadCount > 0) {
            badgeEl.textContent = unreadCount;
            badgeEl.style.display = 'flex';
            if (itemEl) itemEl.classList.add('unread');
        } else {
            badgeEl.style.display = 'none';
            if (itemEl) itemEl.classList.remove('unread');
        }
    }
}

function marcarMensagensComoLidas() {
    const uid = auth.currentUser?.uid;
    if (!uid) return;
    
    db.collection("system_messages")
        .where("userUid", "==", uid)
        .where("read", "==", false)
        .get()
        .then(snapshot => {
            if (snapshot.empty) return;
            const batch = db.batch();
            snapshot.forEach(doc => {
                batch.update(doc.ref, { read: true });
            });
            return batch.commit();
        })
        .catch(err => console.error("Erro ao marcar mensagens como lidas:", err));
}

function renderSystemMessages() {
    const area = document.getElementById('chatMessages');
    if (!area) return;
    
    area.innerHTML = '';
    
    let lastDateStr = '';
    
    systemMessages.forEach(msg => {
        let timeStr = '12:00';
        let dateStr = 'Hoje';
        if (msg.createdAt) {
            const date = msg.createdAt.toDate ? msg.createdAt.toDate() : new Date();
            timeStr = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
            dateStr = date.toLocaleDateString('pt-BR');
        }
        
        if (dateStr !== lastDateStr) {
            area.innerHTML += `
                <div class="chat-date-divider">
                    <span>${dateStr === new Date().toLocaleDateString('pt-BR') ? 'Hoje' : dateStr}</span>
                </div>
            `;
            lastDateStr = dateStr;
        }
        
        const isMe = msg.isMe;
        const wrapperClass = isMe ? 'msg-outgoing' : 'msg-incoming';
        const statusIcon = isMe ? '<i class="ph-fill ph-check-circle msg-status" style="color: #3b82f6;"></i>' : '';
        
        const msgText = msg.text || (msg.title ? `<strong>${sanitizeHTML(msg.title)}</strong><br>${sanitizeHTML(msg.message)}` : sanitizeHTML(msg.message || ''));
        area.innerHTML += `
            <div class="msg-wrapper ${wrapperClass}">
                <div class="msg-bubble">
                    ${msg.text ? sanitizeHTML(msg.text) : msgText}
                    <div class="msg-meta">
                        <span class="msg-time">${sanitizeHTML(timeStr)}</span>
                        ${statusIcon}
                    </div>
                </div>
            </div>
        `;
    });
    
    setTimeout(() => {
        area.scrollTop = area.scrollHeight;
    }, 50);
}

// Expondo globalmente para o HTML
window.openChatDetail = openChatDetail;
window.sanitizeInput = sanitizeInput;
window.validateFile = validateFile;
window.resetSessionTimer = resetSessionTimer;
window.togglePassVisibility = togglePassVisibility;
window.sanitizeHTML = sanitizeHTML;
window.validateEmail = validateEmail;
window.validateCPF = validateCPF;
window.validateCNPJ = validateCNPJ;
window.startFreightListener = startFreightListener;
window.maskMoney = maskMoney;
window.maskPhone = maskPhone;
window.maskCPF = maskCPF;
window.maskCNPJ = maskCNPJ;
window.checkPasswordRequirements = checkPasswordRequirements;
window.showToast = showToast;
window.navTo = navTo;
window.goBack = goBack;
window.goHome = goHome;
window.setRole = setRole;
window.updateNavbar = updateNavbar;
window.openFilters = openFilters;
window.closeFilters = closeFilters;
window.aplicarFiltros = aplicarFiltros;
window.limparFiltros = limparFiltros;
window.togglePill = togglePill;
window.abrirEdicaoFrete = abrirEdicaoFrete;
window.fecharEdicaoFrete = fecharEdicaoFrete;
window.iniciarCadastro = iniciarCadastro;
window.irParaVeiculo = irParaVeiculo;
window.irParaSenha = irParaSenha;
window.finalizarCadastro = finalizarCadastro;
window.preencherPerfil = preencherPerfil;
window.verificarEmailDisponivel = verificarEmailDisponivel;
window.preencherCamposCadastroGoogle = preencherCamposCadastroGoogle;
window.restaurarBotoesCadastroPadrao = restaurarBotoesCadastroPadrao;
window.finalizarCadastroGoogle = finalizarCadastroGoogle;
window.openPhotoActionSheet = openPhotoActionSheet;
window.closePhotoActionSheet = closePhotoActionSheet;
window.toggleEditProfile = toggleEditProfile;
window.handleUpload = handleUpload;
window.handleProfilePhoto = handleProfilePhoto;
window.salvarCadastroMotorista = salvarCadastroMotorista;
window.solicitarSaque = solicitarSaque;
window.toggleStatus = toggleStatus;
window.aceitarFrete = aceitarFrete;
window.renderFretes = renderFretes;
window.openFreight = openFreight;
window.buscarFretes = buscarFretes;
window.renderChats = renderChats;
window.enviarMensagem = enviarMensagem;
window.loginComGoogle = loginComGoogle;
window.handleContinuar = handleContinuar;
window.fazerLogin = fazerLogin;
window.publicarFrete = publicarFrete;
window.salvarEdicaoFrete = salvarEdicaoFrete;
window.concluirFrete = async function(id) {
    if(!confirm('Tem certeza que deseja marcar esta carga como concluÃ­da?')) return;
    try {
        await db.collection("freights").doc(id).update({ status: 'entregue' });
        showToast('Carga concluÃ­da com sucesso!');
    } catch(err) {
        console.error(err);
        showToast('Erro ao concluir carga.', 'error');
    }
};
window.cancelarFrete = async function(id) {
    if(!confirm('Tem certeza que deseja cancelar esta carga?')) return;
    try {
        await db.collection("freights").doc(id).update({ status: 'cancelado' });
        showToast('Carga cancelada!');
    } catch(err) {
        console.error(err);
        showToast('Erro ao cancelar carga.', 'error');
    }
};
window.logout = logout;
window.fecharModalLogout = fecharModalLogout;
window.confirmarLogoutExec = confirmarLogoutExec;
window.abrirModalDeleteAccount = abrirModalDeleteAccount;
window.fecharModalDeleteAccount = fecharModalDeleteAccount;
window.confirmDeleteAccount = confirmDeleteAccount;
window.setShipperHistoryTab = setShipperHistoryTab;
window.renderShipperHistory = renderShipperHistory;

window.navHistory = navHistory;
window.currentUserRole = currentUserRole;
window.userData = userData;
window.db = db;
window.auth = auth;
window.firebase = firebase;

// ImplementaÃ§Ãµes do HistÃ³rico do Embarcador
function setShipperHistoryTab(tab, element) {
    currentShipperHistoryTab = tab;
    const tabs = document.querySelectorAll('#shipperHistoryTabs .tag');
    tabs.forEach(t => {
        t.classList.remove('active');
        t.style.background = '';
        t.style.color = '';
    });
    if (element) {
        element.classList.add('active');
        element.style.background = 'var(--primary)';
        element.style.color = 'white';
    }
    renderShipperHistory();
}

function renderShipperHistory() {
    const listArea = document.getElementById('shipperHistoryList');
    if (!listArea) return;
    if (userData && userData.role !== 'shipper') {
        listArea.innerHTML = '';
        return;
    }
    const targetStatus = currentShipperHistoryTab === 'concluida' ? 'entregue' : 'cancelado';
    const historyFreites = fretes.filter(f => f.shipperUid === auth.currentUser?.uid && f.status === targetStatus);
    
    let html = '';
    if (historyFreites.length === 0) {
        html = `
            <div class="text-center" style="padding: 40px 24px; color: var(--text-muted);">
                <i class="ph ph-clock-counter-clockwise" style="font-size: 48px; margin-bottom: 16px; color: var(--text-muted); opacity: 0.5;"></i>
                <p style="font-size: 14px; font-weight: 500;">Nenhum envio ${currentShipperHistoryTab === 'concluida' ? 'concluÃ­do' : 'cancelado'} ainda.</p>
            </div>
        `;
    } else {
        historyFreites.forEach(frete => {
            const dateStr = frete.createdAt ? new Date(frete.createdAt.seconds * 1000).toLocaleDateString('pt-BR') : new Date().toLocaleDateString('pt-BR');
            const badgeClass = targetStatus === 'entregue' ? 'status-entregue' : 'status-pendente';
            const badgeIcon = targetStatus === 'entregue' ? 'ph-fill ph-check-circle' : 'ph-fill ph-x-circle';
            const badgeLabel = targetStatus === 'entregue' ? 'Entregue com Sucesso' : 'Cancelado';
            
            html += `
                <div class="freight-card" style="opacity: 0.9;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                        <div class="status-badge ${badgeClass}" style="margin:0;">
                            <i class="${badgeIcon}"></i> ${badgeLabel}
                        </div>
                        <span style="font-size: 12px; color: var(--text-muted); font-weight: 600;">${dateStr}</span>
                    </div>
                    <div class="route">
                        <span>${sanitizeHTML(frete.origem)}</span>
                        <i class="ph ph-arrow-right route-arrow"></i>
                        <span>${sanitizeHTML(frete.destino)}</span>
                    </div>
                    <div class="value" style="${targetStatus === 'cancelado' ? 'color: var(--text-muted); text-decoration: line-through;' : ''}">
                        R$ ${sanitizeHTML(frete.valor)}
                    </div>
                </div>
            `;
        });
    }
    listArea.innerHTML = html;
}

// ====== CONTROLLER MULTI-STEP DE PUBLICAÃ‡ÃƒO DE CARGA ======
let publishStep = 1;

function resetPublishStep() {
    publishStep = 1;
    // Limpa campos
    const origemInput = document.getElementById('origem');
    const destinoInput = document.getElementById('destino');
    const telefoneContatoInput = document.getElementById('telefoneContato');
    const whatsappContatoInput = document.getElementById('whatsappContato');
    const tipoCargaSelect = document.getElementById('tipoCarga');
    const veiculoSelect = document.getElementById('veiculo');
    const valorFreteInput = document.getElementById('valorFrete');
    const obsCargaInput = document.getElementById('obsCarga');

    if (origemInput) origemInput.value = '';
    if (destinoInput) destinoInput.value = '';
    if (telefoneContatoInput) telefoneContatoInput.value = '';
    if (whatsappContatoInput) whatsappContatoInput.value = '';
    if (tipoCargaSelect) tipoCargaSelect.value = '';
    if (veiculoSelect) veiculoSelect.value = '';
    if (valorFreteInput) valorFreteInput.value = '';
    if (obsCargaInput) obsCargaInput.value = '';

    updatePublishStep();
}

function prevPublishStep() {
    if (publishStep === 1) {
        goBack();
    } else {
        publishStep--;
        updatePublishStep();
    }
}

function nextPublishStep(btn) {
    if (publishStep === 1) {
        const oVal = document.getElementById('origem').value.trim();
        const dVal = document.getElementById('destino').value.trim();
        if (!oVal || !dVal) {
            showToast('Por favor, informe a origem e o destino da carga.', 'error');
            return;
        }
        publishStep++;
        updatePublishStep();
    } else if (publishStep === 2) {
        const tVal = document.getElementById('telefoneContato').value.trim();
        const wVal = document.getElementById('whatsappContato').value.trim();
        if (!tVal || !wVal) {
            showToast('Por favor, informe as informaÃ§Ãµes de contato.', 'error');
            return;
        }
        publishStep++;
        updatePublishStep();
    } else if (publishStep === 3) {
        const typeSelect = document.getElementById('tipoCarga').value;
        const vehicleSelect = document.getElementById('veiculo').value;
        const priceVal = document.getElementById('valorFrete').value.trim();
        
        if (!typeSelect) {
            showToast('Selecione o tipo de carga.', 'error');
            return;
        }
        if (!vehicleSelect) {
            showToast('Selecione o tipo de veÃ­culo.', 'error');
            return;
        }
        if (!priceVal || priceVal === 'R$ 0,00') {
            showToast('Informe o valor ofertado para o frete.', 'error');
            return;
        }

        // Se passar nas validaÃ§Ãµes finais, publica a carga!
        publicarFrete(btn);
    }
}

function updatePublishStep() {
    // Esconde/mostra painÃ©is
    for (let i = 1; i <= 3; i++) {
        const panel = document.getElementById(`publishStep${i}`);
        if (panel) {
            panel.style.display = i === publishStep ? 'flex' : 'none';
        }
    }

    // Atualiza Stepper progress line
    const stepperLine = document.getElementById('stepperProgressLine');

    if (stepperLine) {
        // Step 1: 0%, Step 2: 40%, Step 3: 80%
        const lineWidth = publishStep === 1 ? '0%' : publishStep === 2 ? '40%' : '80%';
        stepperLine.style.width = lineWidth;
    }

    // Atualiza Stepper indicators
    for (let i = 1; i <= 3; i++) {
        const indicator = document.getElementById(`step${i}Indicator`);
        if (indicator) {
            const numBox = indicator.querySelector('.step-num');
            const labelText = indicator.querySelector('.step-label');

            if (i < publishStep) {
                // ConcluÃ­do
                indicator.classList.add('completed');
                indicator.classList.remove('active');
                if (numBox) {
                    numBox.style.background = '#22c55e';
                    numBox.style.color = '#fff';
                    numBox.innerHTML = '<i class="ph ph-check" style="font-size: 16px; font-weight: bold;"></i>';
                }
                if (labelText) {
                    labelText.style.color = '#22c55e';
                }
            } else if (i === publishStep) {
                // Ativo
                indicator.classList.remove('completed');
                indicator.classList.add('active');
                if (numBox) {
                    numBox.style.background = 'var(--orange)';
                    numBox.style.color = '#fff';
                    numBox.innerHTML = i;
                }
                if (labelText) {
                    labelText.style.color = 'var(--orange)';
                }
            } else {
                // Futuro
                indicator.classList.remove('completed', 'active');
                if (numBox) {
                    numBox.style.background = '#e2e8f0';
                    numBox.style.color = '#94a3b8';
                    numBox.innerHTML = i;
                }
                if (labelText) {
                    labelText.style.color = '#94a3b8';
                }
            }
        }
    }

    // Atualiza botÃµes do Footer
    const cancelBtn = document.getElementById('btnPublishCancel');
    const nextBtn = document.getElementById('btnPublishNext');

    if (cancelBtn) {
        cancelBtn.textContent = publishStep === 1 ? 'Cancelar' : 'Voltar';
    }

    if (nextBtn) {
        if (publishStep === 3) {
            nextBtn.innerHTML = 'Publicar <i class="ph ph-paper-plane-tilt" id="btnPublishNextIcon"></i>';
            nextBtn.style.background = '#22c55e';
            nextBtn.style.borderColor = '#22c55e';
            nextBtn.style.boxShadow = '0 4px 14px rgba(34, 197, 94, 0.25)';
        } else {
            nextBtn.innerHTML = 'PrÃ³ximo Passo <i class="ph ph-arrow-right" id="btnPublishNextIcon"></i>';
            nextBtn.style.background = 'var(--orange)';
            nextBtn.style.borderColor = 'var(--orange)';
            nextBtn.style.boxShadow = '0 4px 14px rgba(249, 115, 22, 0.25)';
        }
    }
}

// Exporta para escopo global
window.prevPublishStep = prevPublishStep;
    window.nextPublishStep = nextPublishStep;
    window.resetPublishStep = resetPublishStep;

    // ====== LEAFLET MAPS & IBGE AUTOCOMPLETE (100% GRATUITO) ======

    let activeMap = null;
    let routeLine = null;
    let originMarker = null;
    let destinationMarker = null;

    window.initLeafletMap = function() {
        const mapElement = document.getElementById('publishMapPreview');
        if (!mapElement) return;

        if (activeMap) {
            activeMap.remove();
            activeMap = null;
        }

        // Inicializa o mapa com o Leaflet focado no Brasil por padrÃ£o
        activeMap = L.map(mapElement, {
            zoomControl: true,
            attributionControl: false
        }).setView([-14.2350, -51.9253], 4);

        // Adiciona camada de mapa gratuita do OpenStreetMap
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19
        }).addTo(activeMap);

        // Tenta obter a geolocalizaÃ§Ã£o do usuÃ¡rio via GPS
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    const lat = position.coords.latitude;
                    const lon = position.coords.longitude;
                    activeMap.setView([lat, lon], 12);

                    L.circleMarker([lat, lon], {
                        radius: 8,
                        fillColor: "#f97316",
                        color: "white",
                        weight: 2,
                        fillOpacity: 1
                    }).addTo(activeMap).bindPopup("VocÃª estÃ¡ aqui");
                },
                () => {
                    console.warn("GeolocalizaÃ§Ã£o nÃ£o permitida ou indisponÃ­vel.");
                }
            );
        }
    };

    let cachedCidades = [];

    async function carregarCidadesIBGE() {
        if (cachedCidades.length > 0) return cachedCidades;
        try {
            const response = await fetch('https://servicodados.ibge.gov.br/api/v1/localidades/municipios');
            const data = await response.json();
            cachedCidades = data.map(item => {
                const uf = item.microrregiao?.mesorregiao?.UF?.sigla || '';
                return `${item.nome}, ${uf}`;
            }).sort();
            return cachedCidades;
        } catch (e) {
            console.error("Erro ao carregar cidades do IBGE:", e);
            return [];
        }
    }

    window.setupIBGEAutocomplete = function() {
        const inputs = ['origem', 'destino'];
        inputs.forEach(id => {
            const input = document.getElementById(id);
            if (!input) return;
            
            let datalist = document.getElementById(`${id}List`);
            if (!datalist) {
                datalist = document.createElement('datalist');
                datalist.id = `${id}List`;
                document.body.appendChild(datalist);
                input.setAttribute('list', datalist.id);
            }

            input.addEventListener('focus', async () => {
                await carregarCidadesIBGE();
            });

            input.addEventListener('input', () => {
                const query = input.value.toLowerCase().trim();
                if (query.length < 2) {
                    datalist.innerHTML = '';
                    return;
                }
                
                const matches = cachedCidades.filter(c => c.toLowerCase().includes(query)).slice(0, 10);
                datalist.innerHTML = matches.map(c => `<option value="${c}"></option>`).join('');
                
                if (cachedCidades.includes(input.value)) {
                    atualizarRotaNoMapa();
                }
            });

            input.addEventListener('blur', () => {
                atualizarRotaNoMapa();
            });
        });
    };

    async function obterCoordenadasNominatim(cidadeEstado) {
        try {
            const query = encodeURIComponent(`${cidadeEstado}, Brasil`);
            const response = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${query}&limit=1`, {
                headers: {
                    'User-Agent': 'PegaFreteApp/1.0'
                }
            });
            const data = await response.json();
            if (data && data.length > 0) {
                return {
                    lat: parseFloat(data[0].lat),
                    lon: parseFloat(data[0].lon)
                };
            }
        } catch (e) {
            console.error("Erro no geocoding Nominatim:", e);
        }
        return null;
    }

    async function atualizarRotaNoMapa() {
        if (!activeMap) return;

        const origem = document.getElementById('origem').value.trim();
        const destino = document.getElementById('destino').value.trim();

        if (!origem || !destino) return;

        const p1 = await obterCoordenadasNominatim(origem);
        const p2 = await obterCoordenadasNominatim(destino);

        if (p1 && p2) {
            if (originMarker) activeMap.removeLayer(originMarker);
            if (destinationMarker) activeMap.removeLayer(destinationMarker);
            if (routeLine) activeMap.removeLayer(routeLine);

            originMarker = L.marker([p1.lat, p1.lon]).addTo(activeMap).bindPopup(`Origem: ${origem}`);
            destinationMarker = L.marker([p2.lat, p2.lon]).addTo(activeMap).bindPopup(`Destino: ${destino}`);

            routeLine = L.polyline([[p1.lat, p1.lon], [p2.lat, p2.lon]], {
                color: '#f97316',
                weight: 4,
                opacity: 0.8,
                dashArray: '5, 10'
            }).addTo(activeMap);

            const group = new L.featureGroup([originMarker, destinationMarker]);
            activeMap.fitBounds(group.getBounds().pad(0.2));
        }
    }

    // ====== SEGURANÃ‡A: GLOBAL ERROR TRACKING FOR DEBUGGING ======
    window.addEventListener('unhandledrejection', event => {
        console.error('Unhandled rejection:', event.reason);
        if (typeof showToast === 'function') {
            showToast(`Erro nÃ£o tratado: ${event.reason?.message || event.reason}`, 'error');
        }
        if (typeof restaurarBotaoGoogle === 'function') restaurarBotaoGoogle();
    });
    window.addEventListener('error', event => {
        console.error('Global error:', event.error);
        if (typeof restaurarBotaoGoogle === 'function') restaurarBotaoGoogle();
    });


