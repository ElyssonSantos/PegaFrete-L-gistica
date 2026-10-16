/**
 * Google Analytics 4 (GA4) Tracking Utility
 * Measurement ID: G-RN6Q4468WZ
 */

export const GA_MEASUREMENT_ID = 'G-RN6Q4468WZ';

/**
 * Safely invokes Google Analytics gtag function or pushes to window.dataLayer
 */
export const sendGtag = (...args) => {
    if (typeof window === 'undefined') return;

    if (typeof window.gtag === 'function') {
        window.gtag(...args);
    } else {
        window.dataLayer = window.dataLayer || [];
        window.dataLayer.push(args);
    }
};

/**
 * Screen ID to Human-Readable Title Mapping
 */
export const SCREEN_TITLES = {
    splash: 'Carregando | PegaFrete',
    auth_entry: 'Boas-Vindas | PegaFrete',
    login: 'Entrar na Conta | PegaFrete',
    choice: 'Escolha de Perfil | PegaFrete',
    register_shipper: 'Cadastro de Embarcador | PegaFrete',
    register_driver: 'Cadastro de Motorista | PegaFrete',
    register_vehicle: 'Cadastro de Veículo | PegaFrete',
    register_driver_docs: 'Documentos do Motorista | PegaFrete',
    register_password: 'Criar Senha de Acesso | PegaFrete',
    driver: 'Painel do Motorista | PegaFrete',
    freights_search: 'Buscar Fretes | PegaFrete',
    shipper: 'Painel do Embarcador | PegaFrete',
    shipper_publish: 'Publicar Frete | PegaFrete',
    shipper_history: 'Histórico de Cargas | PegaFrete',
    freightDetails: 'Detalhes do Frete | PegaFrete',
    terms_screen: 'Termos e Condições | PegaFrete',
    privacy_screen: 'Política de Privacidade | PegaFrete',
    about_screen: 'Sobre Nós | PegaFrete',
    profile: 'Perfil do Usuário | PegaFrete',
    profile_personal_data: 'Dados Pessoais | PegaFrete',
    profile_business_data: 'Dados da Empresa | PegaFrete',
    profile_update_email: 'Atualizar E-mail | PegaFrete',
    profile_security_docs: 'Documentos e Segurança | PegaFrete',
    profile_account: 'Configurações da Conta | PegaFrete',
    profile_support: 'Ajuda e Suporte | PegaFrete',
    financial: 'Financeiro e Saldo | PegaFrete',
    chat: 'Mensagens e Conversas | PegaFrete',
    chat_detail: 'Conversa | PegaFrete',
    support: 'Central de Suporte | PegaFrete',
    about_app: 'Sobre o Aplicativo | PegaFrete',
    faq: 'Perguntas Frequentes | PegaFrete',
    cookies_screen: 'Política de Cookies | PegaFrete'
};

/**
 * Tracks route / page view changes in the Single Page Application
 */
export const trackPageView = (path, title) => {
    const pageTitle = title || document.title || 'PegaFrete | Logística Inteligente';
    const pageLocation = typeof window !== 'undefined' ? window.location.href : '';

    sendGtag('config', GA_MEASUREMENT_ID, {
        page_path: path,
        page_title: pageTitle,
        page_location: pageLocation
    });

    sendGtag('event', 'page_view', {
        page_path: path,
        page_title: pageTitle,
        page_location: pageLocation
    });
};

/**
 * Tracks screen change specifically for PegaFrete SPA
 */
export const trackScreenView = (screenId) => {
    const title = SCREEN_TITLES[screenId] || `${screenId} | PegaFrete`;
    document.title = title;
    const path = '#' + screenId;

    trackPageView(path, title);

    sendGtag('event', 'screen_view', {
        app_name: 'PegaFrete',
        screen_name: screenId,
        screen_title: title
    });

    // Re-observe sections for newly displayed screen
    setTimeout(() => {
        observeSections();
    }, 200);
};

/**
 * Tracks visibility of specific sections within pages
 */
export const trackSectionView = (sectionName, path) => {
    const currentPath = path || (typeof window !== 'undefined' ? (window.location.hash || window.location.pathname) : '');

    sendGtag('event', 'section_view', {
        event_category: 'Section',
        section_name: sectionName,
        page_path: currentPath
    });
};

/**
 * Tracks clicks on buttons, navigation items and interactive controls
 */
export const trackButtonClick = (buttonName, details = {}) => {
    const currentPath = typeof window !== 'undefined' ? (window.location.hash || window.location.pathname) : '';

    sendGtag('event', 'button_click', {
        event_category: 'Button',
        button_name: buttonName,
        page_path: currentPath,
        ...details
    });
};

/**
 * Custom event helper
 */
export const trackEvent = (eventName, params = {}) => {
    sendGtag('event', eventName, params);
};

/**
 * Extracts a readable label for any interactive element
 */
function getElementLabel(el) {
    const aria = el.getAttribute('aria-label');
    if (aria && aria.trim()) return aria.trim();

    const title = el.getAttribute('title');
    if (title && title.trim()) return title.trim();

    const dataName = el.getAttribute('data-button-name') || el.getAttribute('data-action');
    if (dataName && dataName.trim()) return dataName.trim();

    // Check inner text
    const text = el.innerText || el.textContent;
    if (text && text.trim()) {
        const cleanText = text.trim().replace(/\s+/g, ' ').slice(0, 60);
        if (cleanText.length > 0) return cleanText;
    }

    // Check input value
    if (el instanceof HTMLInputElement && el.value) {
        return el.value;
    }

    // Check onclick attribute
    const onclickAttr = el.getAttribute('onclick');
    if (onclickAttr) {
        if (onclickAttr.includes('goBack')) return 'Botão Voltar';
        if (onclickAttr.includes('goHome')) return 'Botão Início';
        if (onclickAttr.includes('openFilters')) return 'Abrir Filtros';
        if (onclickAttr.includes('closeFilters')) return 'Fechar Filtros';
        if (onclickAttr.includes('limparFiltros')) return 'Limpar Filtros';
        if (onclickAttr.includes('aplicarFiltros')) return 'Aplicar Filtros';
        if (onclickAttr.includes('publicarFrete')) return 'Publicar Frete';
        if (onclickAttr.includes('loginComGoogle')) return 'Entrar com Google';
        if (onclickAttr.includes('fazerLogin')) return 'Entrar com E-mail';
        if (onclickAttr.includes('solicitarSaque')) return 'Solicitar Saque';
        if (onclickAttr.includes('logout')) return 'Sair da Conta';
        if (onclickAttr.includes('navTo')) {
            const match = onclickAttr.match(/navTo\(['"]([^'"]+)['"]\)/);
            if (match && match[1]) {
                const targetScreen = match[1];
                return `Navegar para ${SCREEN_TITLES[targetScreen] || targetScreen}`;
            }
        }
    }

    // Check icon inside
    const icon = el.querySelector('i[class*="ph-"]');
    if (icon) {
        const iconClasses = icon.className.split(' ');
        const phClass = iconClasses.find(c => c.startsWith('ph-'));
        if (phClass) {
            const iconName = phClass.replace('ph-', '');
            return `Ícone ${iconName}`;
        }
    }

    const id = el.getAttribute('id');
    if (id) return id;

    const name = el.getAttribute('name');
    if (name) return name;

    return 'Botão sem identificação';
}

/**
 * Resolves the parent section name of an element
 */
function getSectionName(el) {
    const sectionEl = el.closest('[data-section]');
    if (sectionEl) {
        const sName = sectionEl.getAttribute('data-section');
        if (sName) return sName;
    }

    const screenEl = el.closest('.screen');
    if (screenEl && screenEl.id) {
        return SCREEN_TITLES[screenEl.id] || screenEl.id;
    }

    if (el.closest('#bottomNav')) return 'Menu Inferior';
    if (el.closest('header, .topbar')) return 'Cabeçalho / Topbar';
    if (el.closest('nav')) return 'Navegação';
    if (el.closest('footer')) return 'Rodapé';
    if (el.closest('dialog, [role="dialog"], [class*="modal"]')) return 'Modal / Diálogo';

    const container = el.closest('section, article, div[class*="glass-card"], div[class*="card"]');
    if (container) {
        const heading = container.querySelector('h1, h2, h3, h4');
        if (heading && heading.textContent && heading.textContent.trim()) {
            return heading.textContent.trim().slice(0, 50);
        }
    }

    return 'Geral';
}

let isClickTrackingInitialized = false;

/**
 * Automatically captures button, link, and interactive control clicks across all pages and sections
 */
export const initGlobalClickTracking = () => {
    if (typeof window === 'undefined' || isClickTrackingInitialized) return;
    isClickTrackingInitialized = true;

    document.addEventListener(
        'click',
        (event) => {
            const target = event.target;
            if (!target) return;

            const clickable = target.closest(
                'button, a, [role="button"], input[type="button"], input[type="submit"], [onclick], .nav-item, .tab-item, .chip'
            );

            if (clickable) {
                const buttonLabel = getElementLabel(clickable);
                const sectionName = getSectionName(clickable);
                const tagName = clickable.tagName.toLowerCase();
                const href = clickable.getAttribute('href') || undefined;

                trackButtonClick(buttonLabel, {
                    button_tag: tagName,
                    button_id: clickable.id || undefined,
                    section: sectionName,
                    destination_url: href
                });
            }
        },
        { capture: true, passive: true }
    );
};

let sectionObserver = null;
const observedSectionsThisPage = new Set();

/**
 * Observes sections on the current page and sends section_view metrics when visible
 */
export const observeSections = () => {
    if (typeof window === 'undefined' || !('IntersectionObserver' in window)) return;

    if (sectionObserver) {
        sectionObserver.disconnect();
    }
    observedSectionsThisPage.clear();

    sectionObserver = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting && entry.intersectionRatio >= 0.2) {
                    const el = entry.target;
                    const sectionName =
                        el.getAttribute('data-section') ||
                        el.querySelector('h1, h2, h3, h4')?.textContent?.trim() ||
                        el.getAttribute('aria-label') ||
                        el.id ||
                        el.tagName.toLowerCase();

                    if (sectionName && !observedSectionsThisPage.has(sectionName)) {
                        observedSectionsThisPage.add(sectionName);
                        trackSectionView(sectionName);
                    }
                }
            });
        },
        { threshold: [0.2] }
    );

    // Observe active screen sections and elements with data-section
    const elements = document.querySelectorAll(
        '.screen.active [data-section], .screen.active section, .screen.active header, .screen.active .glass-card, [data-section], #bottomNav'
    );

    elements.forEach((el) => {
        sectionObserver.observe(el);
    });
};

/**
 * Initializes Google Analytics listeners and initial page track
 */
export const initAnalytics = () => {
    if (typeof window === 'undefined') return;

    window.gtagAnalytics = {
        sendGtag,
        trackPageView,
        trackScreenView,
        trackSectionView,
        trackButtonClick,
        trackEvent
    };

    initGlobalClickTracking();

    // Determine initial screen
    const initialScreen = window.location.hash ? window.location.hash.replace('#', '') : 'splash';
    trackScreenView(initialScreen);
};
