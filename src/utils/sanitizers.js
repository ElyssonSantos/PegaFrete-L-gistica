export function sanitizeInput(str, maxLen = 500) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .trim()
        .slice(0, maxLen);
}

export function sanitizeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
