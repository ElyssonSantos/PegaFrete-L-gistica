export function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

export function validateCPF(cpf) {
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

export function validateCNPJ(cnpj) {
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

export function checkPasswordRequirements(val) {
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
