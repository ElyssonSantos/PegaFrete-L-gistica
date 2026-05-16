import { describe, it, expect } from 'vitest';

// Simulating the validators from main.js since main.js is coupled to window/DOM
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

function sanitizeInput(str, maxLen = 500) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .trim()
        .slice(0, maxLen);
}

describe('Security & Validation Tests', () => {
    it('should validate emails correctly', () => {
        expect(validateEmail('test@pegafrete.com')).toBe(true);
        expect(validateEmail('invalid-email')).toBe(false);
        expect(validateEmail('test@domain')).toBe(false);
    });

    it('should sanitize inputs preventing XSS', () => {
        const dirty = '<script>alert(1)</script>hello';
        const clean = sanitizeInput(dirty);
        expect(clean).toBe('scriptalert(1)/scripthello');
        
        const href = 'javascript:void(0)';
        expect(sanitizeInput(href)).toBe('void(0)');
    });

    it('should enforce max length in sanitizeInput', () => {
        const longStr = 'a'.repeat(600);
        expect(sanitizeInput(longStr, 100).length).toBe(100);
    });
});
