import firebase from 'firebase/compat/app';
import 'firebase/compat/auth';
import 'firebase/compat/firestore';
import 'firebase/compat/storage';

console.clear();


const logo = `
██████╗ ███████╗ ██████╗  █████╗ ███████╗██████╗ ███████╗████████╗███████╗
██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝
██████╔╝█████╗  ██║  ███╗███████║█████╗  ██████╔╝█████╗     ██║   █████╗
██╔═══╝ ██╔══╝  ██║   ██║██╔══██║██╔══╝  ██╔══██╗██╔══╝     ██║   ██╔══╝
██║     ███████╗╚██████╔╝██║  ██║██║     ██║  ██║███████╗   ██║   ███████╗
╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
`;

console.log(
    "%c" + logo,
    "color: #22c55e; font-family: monospace; font-weight: bold;"
);

console.log(
    "%cSe você está vendo isso, saiba que todo acesso é monitorado. 💚",
    "color: #ffffff; background: #111827; padding: 6px 10px; border-radius: 6px;"
);


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

// ==========================================
// PROTEÇÃO DE FRONTEND E ANTI-DEVTOOLS
// ==========================================

// Bloqueia clique com botão direito
document.addEventListener('contextmenu', event => event.preventDefault());

// Bloqueia atalhos comuns de inspeção
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
    // Ctrl+U ou Cmd+U (Ver Código Fonte)
    if (event.ctrlKey && event.keyCode === 85) {
        event.preventDefault();
        return false;
    }
    // Ctrl+S ou Cmd+S (Salvar página)
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

// ====== SEGURANÇA: SANITIZAÇÃO E VALIDAÇÃO ======

/**
 * Client-side input sanitization (Defense in Depth)
 * Firestore Security Rules fornecem a proteção primária.
 * Esta camada adicional impede injeção de HTML/JS antes de gravar.
 */
function sanitizeInput(str, maxLen = 500) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .trim()
        .slice(0, maxLen);
}

// ====== SEGURANÇA: LOGS E MONITORAMENTO ======
async function logSecurityEvent(event, details) {
    try {
        const user = auth.currentUser;
        const uid = user ? user.uid : 'unauthenticated';

        // Em produção, isso gravaria no Firestore (coleção security_logs)
        // Apenas o backend ou o próprio usuário pode ler seus logs.
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
        console.error('Falha ao gravar log de segurança', err);
    }
}

// ====== SEGURANÇA: VALIDAÇÃO DE ARQUIVOS ======
function validateFile(file, isProfilePhoto = false) {
    if (!file) return { valid: false, error: 'Nenhum arquivo selecionado.' };

    // 1. Validar tamanho
    const maxSize = isProfilePhoto ? 10 * 1024 * 1024 : 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
        return { valid: false, error: `Arquivo muito grande. O limite é ${maxSize / (1024 * 1024)}MB.` };
    }

    // 2. Validar MIME Type (extensões)
    const allowedTypes = isProfilePhoto
        ? ['image/jpeg', 'image/png', 'image/webp']
        : ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];

    if (!allowedTypes.includes(file.type)) {
        return { valid: false, error: 'Formato de arquivo não permitido. Use JPG, PNG, WEBP ou PDF.' };
    }

    // 3. Validar nome do arquivo (evitar path traversal)
    if (file.name.includes('..') || file.name.endsWith('.exe') || file.name.endsWith('.sh') || file.name.endsWith('.svg')) {
        return { valid: false, error: 'Nome ou tipo de arquivo suspeito.' };
    }

    return { valid: true };
}

// Valores permitidos (validação por whitelist)
const VALID_TIPOS = ['Carga Leve', 'Fracionada', 'Carga Fechada', 'Complemento'];
const VALID_VEICULOS = ['3/4', 'Toco', 'Fiorino', 'Truck', 'Bitruck', 'Carreta LS', 'Bitrem', 'Rodotrem', 'Vanderléia', 'Caçamba', 'Silo', 'Graneleiro', 'Plataforma', 'Prancha', 'Tanque', 'Sider', 'Baú Refrigerado', 'Baú'];

// ====== SESSION TIMEOUT (24 hours) ======
let sessionTimer = null;
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
let currentShipperHistoryTab = 'concluida';

function resetSessionTimer() {
    if (sessionTimer) clearTimeout(sessionTimer);
    sessionTimer = setTimeout(() => {
        if (auth.currentUser) {
            showToast('Sessão expirada por inatividade.', 'info');
            logout();
        }
    }, SESSION_TIMEOUT);
}

// Reset timer on user activity
['click', 'keypress', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetSessionTimer, { passive: true });
});

// ====== FUNÇÕES DE SEGURANÇA ======

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

// Validação de e-mail
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// Validação algorítmica de CPF
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

// Validação algorítmica de CNPJ
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
    { id: 2, origem: 'Salvador', destino: 'Ilhéus', valor: '980,00', tipo: 'Fracionada', veiculo: 'Toco', status: 'pendente', obs: 'Carga urgente para hoje.' }
];

let mensagens = [];
let systemMessages = [];
let systemMessagesListener = null;

window.onload = () => {
    renderChats();
    navTo('splash');

    // Monitora o estado de autenticação via Firebase
    auth.onAuthStateChanged(async (user) => {
        if (isRegisteringProcess) {
            console.log("Ignorando redirecionamento automático do onAuthStateChanged durante o cadastro.");
            return;
        }
        if (user) {
            try {
                // Sincroniza/Salva a entrada em public_emails para garantir que o fluxo de verificação funcione
                if (user.email) {
                    const emailKey = user.email.toLowerCase().trim();
                    const providerId = user.providerData[0]?.providerId === 'google.com' ? 'google' : 'password';
                    db.collection("public_emails").doc(emailKey).set({
                        provider: providerId
                    }, { merge: true }).catch(err => console.warn("Erro ao salvar public_emails:", err));
                }

                const docRef = await db.collection("users").doc(user.uid).get();
                if (docRef.exists) {
                    userData = docRef.data();
                    preencherPerfil();
                    setRole(userData.role || 'driver');
                    startFreightListener();
                    startSystemMessagesListener();
                } else {
                    // Se logou com Google mas não tem perfil, vai escolher o papel
                    preencherCamposCadastroGoogle(user);
                    navTo('choice');
                }
            } catch (error) {
                console.error("Erro ao verificar documento do usuário:", error);
                navTo('auth_entry');
            }
        } else {
            if (systemMessagesListener) {
                systemMessagesListener();
                systemMessagesListener = null;
            }
            restaurarBotoesCadastroPadrao();
            navTo('auth_entry');
        }
    });
};

// ====== LÓGICA DE AUTENTICAÇÃO (NOVA) ======

async function verificarEmailDisponivel(email) {
    const emailKey = email.toLowerCase().trim();
    
    // Se o usuário logado no Firebase Auth tem o mesmo e-mail, está tudo bem (ele está apenas completando o perfil)
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

    // Fallback secundário para fetchSignInMethodsForEmail
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

    // Altera texto dos botões de cadastro para Google
    const btnAvancarShipper = document.querySelector('#register_shipper button.btn-orange');
    if (btnAvancarShipper) {
        btnAvancarShipper.innerHTML = `Finalizar Cadastro <i class="ph ph-check-circle"></i>`;
    }
    const btnAvancarVehicle = document.querySelector('#register_vehicle button.btn-orange');
    if (btnAvancarVehicle) {
        btnAvancarVehicle.innerHTML = `Finalizar Cadastro <i class="ph ph-check-circle"></i>`;
    }
}

function restaurarBotoesCadastroPadrao() {
    const btnAvancarShipper = document.querySelector('#register_shipper button.btn-orange');
    if (btnAvancarShipper) {
        btnAvancarShipper.innerHTML = `Próxima Etapa <i class="ph ph-arrow-right"></i>`;
    }
    const btnAvancarVehicle = document.querySelector('#register_vehicle button.btn-orange');
    if (btnAvancarVehicle) {
        btnAvancarVehicle.innerHTML = `Avançar para Senha <i class="ph ph-arrow-right"></i>`;
    }
    
    const regShipperEmailEl = document.getElementById('regShipperEmail');
    if (regShipperEmailEl) regShipperEmailEl.disabled = false;
    const regDriverEmailEl = document.getElementById('regDriverEmail');
    if (regDriverEmailEl) regDriverEmailEl.disabled = false;
}

async function finalizarCadastroGoogle() {
    const user = auth.currentUser;
    if (!user) {
        showToast('Usuário não autenticado.', 'error');
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

    // 1. Salva o perfil do usuário no Firestore
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
        showToast('Por favor, insira um e-mail válido.', 'error');
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

        // Verifica se o e-mail já possui conta vinculada
        const check = await verificarEmailDisponivel(email);
        
        btn.innerHTML = original;
        btn.disabled = false;

        if (!check.disponivel) {
            if (check.provider === 'google') {
                showToast('Esta conta utiliza o Login com Google. Redirecionando...', 'info');
                // Chama o login com Google automaticamente
                const googleBtn = document.querySelector('.btn-google');
                loginComGoogle(googleBtn);
            } else {
                navTo('login');
            }
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
        const result = await auth.signInWithPopup(provider);
        const user = result.user;

        // O onAuthStateChanged cuidará do redirecionamento
        showToast('Login com Google realizado!', 'success');
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
        freightListenerUnsubscribe(); // Previne múltiplos listeners
    }
    let isInitialLoad = true;
    
    freightListenerUnsubscribe = db.collection("freights").orderBy("createdAt", "desc").limit(20).onSnapshot((snapshot) => {
        const novosDados = [];
        snapshot.forEach(doc => novosDados.push({ id: doc.id, ...doc.data() }));

        // Verifica se há novas cargas para notificar (se não for a carga que eu acabei de postar)
        if (!isInitialLoad && fretes.length > 0 && novosDados.length > fretes.length) {
            const ultimaCarga = novosDados[0];
            if (userData && userData.role === 'driver' && window.isDriverOnline && ultimaCarga.shipperUid !== auth.currentUser?.uid) {
                showToast(`Nova carga disponível: ${ultimaCarga.origem} para ${ultimaCarga.destino}`, 'info');
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
    // Gerenciamento da flag isRegisteringProcess para evitar auto-redirecionamento da sessão
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

    // Altera texto do botão de perfil
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

// Modal de Edição (Embarcador)
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
            showToast('Tipo de carga ou veículo inválido.', 'error');
            logSecurityEvent('INVALID_INPUT', `Tipo de carga ou veículo inválido editado por ${auth.currentUser?.uid}`);
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
        showToast('As informações da carga foram atualizadas.');
    } catch (error) {
        btn.innerHTML = original;
        btn.disabled = false;
        showToast(error.message || 'Erro ao salvar alterações.', 'error');
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
        showToast('Insira um número válido.', 'error');
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
        showToast('Código enviado com sucesso!', 'success');
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
        showToast('O código deve ter 6 dígitos.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;

    try {
        // Confirma o código no Firebase
        const userCredential = await confirmationResult.confirm(code);
        const user = userCredential.user;

        btn.innerHTML = original;

        // Agora que o telefone está validado, verificamos se ele já tem um perfil no banco
        const querySnapshot = await db.collection("users").where("telefone", "==", tempPhone).get();

        if (!querySnapshot.empty) {
            // Já tem cadastro, vai pro Login (onde ele põe o email e a senha que ele criou antes)
            // Ou podemos fazer o login direto se ele já tiver email salvo, mas o usuário pediu senha.
            navTo('login');
        } else {
            // Não tem cadastro, vai escolher o perfil
            navTo('choice');
        }
    } catch (error) {
        btn.innerHTML = original;
        showToast('Código inválido ou expirado.', 'error');
    }
}

async function fazerLogin(btn) {
    const email = document.getElementById('loginEmail').value;
    const pass = document.getElementById('loginPassword').value;

    if (!email || !pass) {
        showToast('Preencha os campos corretamente.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Autenticando...`;

    try {
        const userCredential = await auth.signInWithEmailAndPassword(email, pass);
        const docRef = await db.collection("users").doc(userCredential.user.uid).get();
        btn.innerHTML = original;

        if (docRef.exists) {
            userData = docRef.data();
            preencherPerfil();
            setRole(userData.role || 'driver');
            showToast('Bem-vindo de volta!');
        } else {
            showToast('Perfil de usuário não encontrado.', 'error');
        }
    } catch (error) {
        btn.innerHTML = original;
        // SECURITY: Generic error message to prevent credential enumeration
        // Don't distinguish between "user not found" and "wrong password"
        if (error.code === 'auth/user-not-found' || error.code === 'auth/invalid-credential') {
            showToast('Credenciais inválidas. Verifique seu e-mail e senha.', 'error');
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
        showToast('Preencha pelo menos os campos obrigatórios.', 'error');
        return;
    }
    if (!validateEmail(userData.email)) {
        showToast('Insira um e-mail válido.', 'error');
        return;
    }
    if (userData.cpf && !validateCPF(userData.cpf)) {
        showToast('CPF inválido. Verifique os dígitos.', 'error');
        return;
    }

    const originalText = btn ? btn.innerHTML : 'Próxima Etapa';
    if (btn) {
        btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;
        btn.disabled = true;
    }

    try {
        const check = await verificarEmailDisponivel(userData.email);
        if (!check.disponivel) {
            if (check.provider === 'google') {
                showToast('Este e-mail já está cadastrado via Google. Faça login com o Google.', 'error');
            } else {
                showToast('Este e-mail já está cadastrado. Faça login ou use outro e-mail.', 'error');
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

async function irParaSenha(btn) {
    if (tempRole === 'shipper') {
        userData.nome = document.getElementById('regShipperName').value.trim();
        userData.email = document.getElementById('regShipperEmail').value.trim();
        userData.telefone = document.getElementById('regShipperPhone').value.trim();
        userData.endereco = document.getElementById('regShipperAddress').value.trim();
        userData.cnpj = document.getElementById('regShipperCnpj').value.trim();
        userData.razao = document.getElementById('regShipperRazao').value.trim();

        if (!userData.nome || !userData.email || !userData.telefone) {
            showToast('Preencha pelo menos os campos obrigatórios.', 'error');
            return;
        }
        if (!validateEmail(userData.email)) {
            showToast('Insira um e-mail válido.', 'error');
            return;
        }
        if (userData.cnpj && !validateCNPJ(userData.cnpj)) {
            showToast('CNPJ inválido. Verifique os dígitos.', 'error');
            return;
        }

        const originalText = btn ? btn.innerHTML : 'Próxima Etapa';
        if (btn) {
            btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Validando...`;
            btn.disabled = true;
        }

        try {
            const check = await verificarEmailDisponivel(userData.email);
            if (!check.disponivel) {
                if (check.provider === 'google') {
                    showToast('Este e-mail já está cadastrado via Google. Faça login com o Google.', 'error');
                } else {
                    showToast('Este e-mail já está cadastrado. Faça login ou use outro e-mail.', 'error');
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
        const selObj = document.getElementById('regDriverVehicle');
        const opt = selObj.options[selObj.selectedIndex];
        if (opt.disabled || opt.value === "") {
            showToast('Por favor, selecione o seu veículo.', 'error');
            return;
        }
        userData.veiculo = opt.value;
    }

    // Se o usuário já está autenticado (ex: Google OAuth), não precisa criar senha!
    // Salva os dados diretamente no Firestore.
    if (auth.currentUser) {
        const originalText = btn ? btn.innerHTML : 'Finalizar';
        if (btn) {
            btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Finalizando...`;
            btn.disabled = true;
        }
        try {
            await finalizarCadastroGoogle();
        } catch (err) {
            console.error(err);
            showToast('Erro ao concluir cadastro: ' + err.message, 'error');
        } finally {
            if (btn) {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        }
        return;
    }

    navTo('register_password');
}

async function finalizarCadastro(btn) {
    const pass1 = document.getElementById('regPassword').value;
    const pass2 = document.getElementById('regPasswordConfirm').value;

    // Validação de senha: 8 dígitos, letra maiúscula, número, caractere especial
    const passRegex = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;
    if (!passRegex.test(pass1)) {
        showToast('A senha não cumpre os requisitos de segurança.', 'error');
        return;
    }

    if (pass1 !== pass2) {
        showToast('As senhas não coincidem.', 'error');
        return;
    }

    const original = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Criando conta...`;

    try {
        // Cria o usuário na Auth do Firebase
        const userCredential = await auth.createUserWithEmailAndPassword(userData.email, pass1);
        const uid = userCredential.user.uid;

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

        // Salva no Firestore
        await db.collection("users").doc(uid).set(cleanUserData);
        userData = cleanUserData; // Atualiza a variável global

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
            ? 'Este e-mail já está em uso.'
            : error.code === 'auth/weak-password'
                ? 'A senha é muito fraca.'
                : 'Erro ao criar conta. Verifique seus dados.';
        showToast(errMsg, 'error');
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

    if (document.getElementById('profileDisplayName')) document.getElementById('profileDisplayName').innerText = userData.nome || userData.razao || 'Usuário';
    
    if (document.getElementById('driverHomeGreeting')) {
        const firstName = (userData.nome || userData.razao || 'Usuário').split(' ')[0];
        document.getElementById('driverHomeGreeting').innerText = `Olá, ${firstName}`;
    }

    if (document.getElementById('profEmail')) document.getElementById('profEmail').value = userData.email || '';
    if (document.getElementById('profPhone')) document.getElementById('profPhone').value = userData.telefone || '';
    if (document.getElementById('profAddress')) document.getElementById('profAddress').value = userData.endereco || '';

    // Estrelas (Rating)
    if (document.getElementById('profileRating')) {
        const rating = userData.rating !== undefined ? Number(userData.rating).toFixed(1) : '5.0';
        document.getElementById('profileRating').innerText = rating;
    }

    // Entregas enviadas / concluídas
    if (document.getElementById('profileDeliveries')) {
        const deliveries = userData.entregas !== undefined ? userData.entregas : 0;
        document.getElementById('profileDeliveries').innerText = deliveries;
    }
    
    if (document.getElementById('profileDeliveriesLabel')) {
        document.getElementById('profileDeliveriesLabel').innerText = userData.role === 'shipper' ? 'Enviadas' : 'Concluídas';
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

    if (userData.role === 'driver' && userData.veiculo) {
        if (document.getElementById('profVehicleGroup')) document.getElementById('profVehicleGroup').style.display = 'block';
        if (document.getElementById('profVehicle')) document.getElementById('profVehicle').value = userData.veiculo;
    } else {
        if (document.getElementById('profVehicleGroup')) document.getElementById('profVehicleGroup').style.display = 'none';
    }

    const avatarUrl = userData.foto || 'https://i.imgur.com/vnYcevV.png';
    if (document.getElementById('profileAvatar')) {
        document.getElementById('profileAvatar').style.backgroundImage = `url('${avatarUrl}')`;
    }
    if (document.getElementById('driverHomeAvatar')) {
        document.getElementById('driverHomeAvatar').style.backgroundImage = `url('${avatarUrl}')`;
    }

    const uploadList = document.getElementById('profileUploadList');
    if (uploadList) {
        if (userData.role === 'shipper') {
            uploadList.innerHTML = `
                <!-- Cartão CNPJ -->
                <div class="upload-item" id="upCNPJ" onclick="handleUpload('upCNPJ', 'Cartão CNPJ')" style="border-radius: 16px; padding: 14px 18px; border: 1.5px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: 0.2s; background: #fafafa; margin: 0;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <i class="ph-fill ph-file-text" style="font-size: 24px; color: var(--orange);"></i>
                        <div style="text-align: left;">
                            <p style="font-weight: 700; font-size: 13px; color: var(--primary); margin: 0 0 2px 0;">Cartão CNPJ</p>
                            <p style="font-size: 11px; color: var(--text-muted); font-weight: 600; margin: 0;">Toque para enviar</p>
                        </div>
                    </div>
                    <i class="ph ph-upload-simple" style="font-size: 18px; color: var(--text-muted);"></i>
                </div>

                <!-- Comprovante de Endereço da Empresa -->
                <div class="upload-item" id="upEnderecoEmpresa" onclick="handleUpload('upEnderecoEmpresa', 'Comprovante de Endereço da Empresa')" style="border-radius: 16px; padding: 14px 18px; border: 1.5px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: 0.2s; background: #fafafa; margin: 0;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <i class="ph-fill ph-house-line" style="font-size: 24px; color: var(--orange);"></i>
                        <div style="text-align: left;">
                            <p style="font-weight: 700; font-size: 13px; color: var(--primary); margin: 0 0 2px 0;">Comprovante de Endereço da Empresa</p>
                            <p style="font-size: 11px; color: var(--text-muted); font-weight: 600; margin: 0;">Toque para enviar</p>
                        </div>
                    </div>
                    <i class="ph ph-upload-simple" style="font-size: 18px; color: var(--text-muted);"></i>
                </div>
            `;
        } else {
            // Transportador (driver)
            uploadList.innerHTML = `
                <!-- CRLV -->
                <div class="upload-item" id="upCRLV" onclick="handleUpload('upCRLV', 'CRLV')" style="border-radius: 16px; padding: 14px 18px; border: 1.5px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: 0.2s; background: #fafafa; margin: 0;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <i class="ph-fill ph-file-text" style="font-size: 24px; color: var(--orange);"></i>
                        <div style="text-align: left;">
                            <p style="font-weight: 700; font-size: 13px; color: var(--primary); margin: 0 0 2px 0;">CRLV</p>
                            <p style="font-size: 11px; color: var(--text-muted); font-weight: 600; margin: 0;">Toque para enviar</p>
                        </div>
                    </div>
                    <i class="ph ph-upload-simple" style="font-size: 18px; color: var(--text-muted);"></i>
                </div>

                <!-- Comprovante de Residência -->
                <div class="upload-item" id="upResidencia" onclick="handleUpload('upResidencia', 'Comprovante de Residência')" style="border-radius: 16px; padding: 14px 18px; border: 1.5px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: 0.2s; background: #fafafa; margin: 0;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <i class="ph-fill ph-house-line" style="font-size: 24px; color: var(--orange);"></i>
                        <div style="text-align: left;">
                            <p style="font-weight: 700; font-size: 13px; color: var(--primary); margin: 0 0 2px 0;">Comprovante de Residência</p>
                            <p style="font-size: 11px; color: var(--text-muted); font-weight: 600; margin: 0;">Toque para enviar</p>
                        </div>
                    </div>
                    <i class="ph ph-upload-simple" style="font-size: 18px; color: var(--text-muted);"></i>
                </div>

                <!-- CPF -->
                <div class="upload-item" id="upCPF" onclick="handleUpload('upCPF', 'CPF')" style="border-radius: 16px; padding: 14px 18px; border: 1.5px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: 0.2s; background: #fafafa; margin: 0;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <i class="ph-fill ph-identification-card" style="font-size: 24px; color: var(--orange);"></i>
                        <div style="text-align: left;">
                            <p style="font-weight: 700; font-size: 13px; color: var(--primary); margin: 0 0 2px 0;">CPF</p>
                            <p style="font-size: 11px; color: var(--text-muted); font-weight: 600; margin: 0;">Toque para enviar</p>
                        </div>
                    </div>
                    <i class="ph ph-upload-simple" style="font-size: 18px; color: var(--text-muted);"></i>
                </div>

                <!-- CNH -->
                <div class="upload-item" id="upCNH" onclick="handleUpload('upCNH', 'CNH')" style="border-radius: 16px; padding: 14px 18px; border: 1.5px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: 0.2s; background: #fafafa; margin: 0;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <i class="ph-fill ph-identification-badge" style="font-size: 24px; color: var(--orange);"></i>
                        <div style="text-align: left;">
                            <p style="font-weight: 700; font-size: 13px; color: var(--primary); margin: 0 0 2px 0;">CNH</p>
                            <p style="font-size: 11px; color: var(--text-muted); font-weight: 600; margin: 0;">Toque para enviar</p>
                        </div>
                    </div>
                    <i class="ph ph-upload-simple" style="font-size: 18px; color: var(--text-muted);"></i>
                </div>
            `;
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
        showToast('Tipo de arquivo não permitido.', 'error');
        return;
    }

    showToast('Processando foto de perfil...', 'info');
    
    try {
        // Otimização: Para evitar erros de CORS e requisições falhas de Storage no console do navegador,
        // salvamos a imagem comprimida em Base64 diretamente no Firestore do usuário.
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
        
        showToast('Você saiu da conta com segurança.', 'info');
        
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

// Controla o modo de edição do perfil
let profileEditMode = false;

function toggleEditProfile() {
    profileEditMode = !profileEditMode;
    const fields = ['profName', 'profRazao', 'profPhone', 'profAddress'];
    const btnEdit = document.getElementById('btnEditProfile');
    const btnSave = document.getElementById('btnSaveProfile');

    if (profileEditMode) {
        // Ativar edição
        fields.forEach(id => {
            const el = document.getElementById(id);
            el.disabled = false;
            el.style.background = '#fff';
            el.style.color = 'var(--text-main)';
            el.style.cursor = 'text';
            el.style.borderColor = 'var(--orange)';
        });
        btnEdit.innerHTML = '<i class="ph ph-x" style="margin-right: 6px;"></i> Cancelar';
        btnEdit.style.borderColor = '#ef4444';
        btnEdit.style.color = '#ef4444';
        btnSave.style.display = 'block';
        // Foca no primeiro campo
        document.getElementById('profName').focus();
    } else {
        // Desativar edição (cancelar)
        fields.forEach(id => {
            const el = document.getElementById(id);
            el.disabled = true;
            el.style.background = '#f1f5f9';
            el.style.color = '#64748b';
            el.style.cursor = 'not-allowed';
            el.style.borderColor = 'var(--border)';
        });
        btnEdit.innerHTML = '<i class="ph ph-pencil-simple" style="margin-right: 6px;"></i> Editar';
        btnEdit.style.borderColor = '';
        btnEdit.style.color = '';
        btnSave.style.display = 'none';
        // Restaurar dados originais
        if (userData) {
            document.getElementById('profName').value = userData.nome || '';
            document.getElementById('profPhone').value = userData.telefone || '';
            document.getElementById('profAddress').value = userData.endereco || '';
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
            showToast('Usuário não autenticado.', 'error');
            logSecurityEvent('UNAUTHENTICATED_ACCESS', 'Tentativa de salvar perfil sem autenticação');
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

        // Firestore protegido por Security Rules (só permite atualizar campos permitidos)
        updatedData.updatedAt = firebase.firestore.FieldValue.serverTimestamp();
        await db.collection('users').doc(user.uid).update(updatedData);
        Object.assign(userData, updatedData);

        btn.innerHTML = original;
        btn.disabled = false;

        // Volta ao modo bloqueado
        profileEditMode = true; // Forçar toggle para desligar
        toggleEditProfile();

        showToast('Dados do perfil atualizados com sucesso!');
    } catch (error) {
        btn.innerHTML = original;
        btn.disabled = false;
        showToast(error.message || 'Erro ao salvar perfil.', 'error');
    }
}

function handleUpload(elementId, type, isButton = false) {
    // OBS: Esta função atualmente simula o upload para o UI.
    // Quando implementada com input type="file" real, chame validateFile(file) antes:
    // const validation = validateFile(file, type === 'Foto');
    // if (!validation.valid) {
    //     showToast(validation.error, 'error');
    //     logSecurityEvent('INVALID_UPLOAD', validation.error);
    //     return;
    // }

    showToast(`Iniciando upload: ${type}...`, 'info');

    const el = document.getElementById(elementId);
    if (isButton && el) {
        el.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Aguarde...`;
    }

    setTimeout(() => {
        if (el && !isButton) {
            if (el.classList.contains('upload-item')) {
                el.classList.add('uploaded');
                const subtitle = el.querySelector('div > div > p:last-child');
                if (subtitle) subtitle.innerText = "Enviado e aguardando validação";
                const iconRight = el.querySelector('i.ph-upload-simple');
                if (iconRight) {
                    iconRight.className = 'ph-fill ph-clock';
                    iconRight.style.color = '#f59e0b';
                    iconRight.style.fontSize = '24px';
                }
            } else {
                el.classList.add('uploaded');
                el.innerHTML = `<i class="ph-fill ph-check-circle"></i><p style="font-size: 13px; font-weight: 600;">Enviado</p>`;
            }
        } else if (el && isButton) {
            if (elementId === 'btnPhoto') {
                el.innerHTML = `<i class="ph-fill ph-check" style="font-size: 18px;"></i>`;
                el.style.background = '#22c55e';
                el.style.borderColor = '#22c55e';
                el.style.color = '#fff';
            } else {
                el.innerHTML = `<i class="ph-fill ph-check-circle"></i> Capturada`;
                el.style.background = '#f0fdf4';
                el.style.borderColor = '#22c55e';
                el.style.color = '#15803d';
            }
        }
        showToast(`${type} enviado com sucesso!`);
    }, 1500);
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
        showToast('Transferência enviada. O valor cairá na sua conta em instantes.');
    }, 2000);
}

window.isDriverOnline = false;
function toggleStatus(btn) {
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
            <span class="status-indicator-text">Disponível para cargas</span>
        `;
        showToast('Você está online e visível para novas cargas!');
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
        showToast('Você agora está invisível no radar.', 'info');
    }
}


function aceitarFrete(btn) {
    const originalText = btn.innerHTML;
    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Reservando carga...`;

    setTimeout(() => {
        btn.innerHTML = `<i class="ph-fill ph-check-circle"></i> Viagem Iniciada!`;
        btn.style.background = '#22c55e';
        showToast('Carga confirmada! Acompanhe os detalhes na área de Chat.');
    }, 1500);
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
                <h3>Sem cargas compatíveis</h3>
                <p>Não encontramos nenhuma carga publicada compatível com seu veículo no momento.</p>
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
                <h3>Nenhuma carga disponível</h3>
                <p>Não há nenhuma publicação de carga ativa no momento.</p>
            </div>
        `;
    } else {
        listFretesSearch.forEach((frete) => {
            const idParam = typeof frete.id === 'string' ? `'${frete.id}'` : frete.id;
            htmlSearch += `
              <div class="premium-freight-card" onclick="openFreight(${idParam})">
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

    // Render para o painel do Embarcador (com botão editar)
    if (areaShipper) {
        let shipperHtml = '';
        listFretesHome.forEach(f => {
            const statusLabel = f.status === 'transito' ? '<i class="ph ph-navigation-arrow"></i> Em trânsito' : '<i class="ph ph-hourglass"></i> Aguardando motorista';
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

    // Atualiza também o histórico do Embarcador
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
    document.getElementById('detailObsText').innerText = frete.obs || 'Nenhuma observação informada.';

    const badges = document.getElementById('detailBadges');
    badges.innerHTML = `
            <div class="tag blue"><i class="ph ph-package"></i> ${sanitizeHTML(frete.tipo)}</div>
            <div class="tag orange"><i class="ph ph-truck"></i> ${sanitizeHTML(frete.veiculo)}</div>
            <div class="tag" style="background: #fef2f2; color: #ef4444;"><i class="ph ph-clock"></i> Carga Imediata</div>
        `;

    navTo('freightDetails');
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

    // Client-side validation (also validated server-side)
    if (!origem || !destino || !valor || !tipo || !veiculo || !telefoneContato || !whatsappContato) {
        showToast('Preencha todas as informações (incluindo contatos) para publicar.', 'error');
        return;
    }

    btn.innerHTML = `<i class="ph ph-spinner ph-spin"></i> Publicando...`;
    btn.disabled = true;

    try {
        // Whitelist validation
        if (!VALID_TIPOS.includes(tipo) || !VALID_VEICULOS.includes(veiculo)) {
            showToast('Tipo de carga ou veículo inválido.', 'error');
            logSecurityEvent('INVALID_INPUT', `Tentativa de publicar carga com veículo/tipo inválido: ${tipo} / ${veiculo}`);
            btn.innerHTML = originalContent;
            btn.disabled = false;
            return;
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
            shipperUid: auth.currentUser.uid,
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
        };

        await db.collection('freights').add(novoFrete);

        showToast('Carga publicada com sucesso! Divulgada em tempo real para os motoristas.');

        // Limpa campos e reseta steps
        resetPublishStep();

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
            sender: 'Você',
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
        mensagens.push({ isMe: true, sender: 'Você', text: text, time: time });
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
    
    document.getElementById('activeChatStatusText').textContent = status;
    
    const avatarImg = document.getElementById('activeChatAvatar');
    if (avatarImg) {
        if (name === 'Pega Frete') {
            avatarImg.src = 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=200&h=200&auto=format&fit=crop';
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
        .where("userUid", "==", uid)
        .orderBy("createdAt", "asc");
        
    systemMessagesListener = ref.onSnapshot(snapshot => {
        systemMessages = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            systemMessages.push({
                id: doc.id,
                ...data
            });
        });
        
        if (systemMessages.length === 0) {
            db.collection("system_messages").add({
                userUid: uid,
                text: "Bem-vindo ao canal oficial do Pega Frete! Aqui você receberá avisos importantes, atualizações do aplicativo e notificações sobre suas cargas.",
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
    if (systemMessages.length === 0) return;
    
    const lastMsg = systemMessages[systemMessages.length - 1];
    
    const previewEl = document.getElementById('systemChatPreview');
    if (previewEl) {
        previewEl.innerHTML = (lastMsg.isMe ? '<i class="ph-fill ph-check-circle" style="color: #3b82f6; margin-right: 4px; font-size: 16px;"></i>' : '') + sanitizeHTML(lastMsg.text);
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
    
    const unreadCount = systemMessages.filter(m => !m.isMe && !m.read).length;
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
        
        area.innerHTML += `
            <div class="msg-wrapper ${wrapperClass}">
                <div class="msg-bubble">
                    ${sanitizeHTML(msg.text)}
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
    if(!confirm('Tem certeza que deseja marcar esta carga como concluída?')) return;
    try {
        await db.collection("freights").doc(id).update({ status: 'entregue' });
        showToast('Carga concluída com sucesso!');
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
window.setShipperHistoryTab = setShipperHistoryTab;
window.renderShipperHistory = renderShipperHistory;

window.navHistory = navHistory;
window.currentUserRole = currentUserRole;
window.userData = userData;
window.db = db;
window.auth = auth;
window.firebase = firebase;

// Implementações do Histórico do Embarcador
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
                <p style="font-size: 14px; font-weight: 500;">Nenhum envio ${currentShipperHistoryTab === 'concluida' ? 'concluído' : 'cancelado'} ainda.</p>
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

// ====== CONTROLLER MULTI-STEP DE PUBLICAÇÃO DE CARGA ======
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
            showToast('Por favor, informe as informações de contato.', 'error');
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
            showToast('Selecione o tipo de veículo.', 'error');
            return;
        }
        if (!priceVal || priceVal === 'R$ 0,00') {
            showToast('Informe o valor ofertado para o frete.', 'error');
            return;
        }

        // Se passar nas validações finais, publica a carga!
        publicarFrete(btn);
    }
}

function updatePublishStep() {
    // Esconde/mostra painéis
    for (let i = 1; i <= 3; i++) {
        const panel = document.getElementById(`publishStep${i}`);
        if (panel) {
            panel.style.display = i === publishStep ? 'flex' : 'none';
        }
    }

    // Atualiza Stepper progress line and bar
    const stepperLine = document.getElementById('stepperProgressLine');
    const stepperBar = document.getElementById('stepperProgressBar');

    if (stepperLine) {
        // Step 1: 0%, Step 2: 40%, Step 3: 80%
        const lineWidth = publishStep === 1 ? '0%' : publishStep === 2 ? '40%' : '80%';
        stepperLine.style.width = lineWidth;
    }

    if (stepperBar) {
        const barWidth = publishStep === 1 ? '33%' : publishStep === 2 ? '66%' : '100%';
        stepperBar.style.width = barWidth;
    }

    // Atualiza Stepper indicators
    for (let i = 1; i <= 3; i++) {
        const indicator = document.getElementById(`step${i}Indicator`);
        if (indicator) {
            const numBox = indicator.querySelector('.step-num');
            const labelText = indicator.querySelector('.step-label');

            if (i < publishStep) {
                // Concluído
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

    // Atualiza botões do Footer
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
            nextBtn.innerHTML = 'Próximo Passo <i class="ph ph-arrow-right" id="btnPublishNextIcon"></i>';
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
