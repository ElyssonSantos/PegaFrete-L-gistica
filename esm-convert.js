const fs = require('fs');

let code = fs.readFileSync('src/scripts/main.js', 'utf8');

const imports = `import firebase from 'firebase/compat/app';
import 'firebase/compat/auth';
import 'firebase/compat/firestore';

`;

code = imports + code;

const funcRegex = /^\s*function\s+([a-zA-Z0-9_]+)\s*\(/gm;
let match;
let exportsToWindow = '\n// Expondo globalmente para o HTML\n';

while ((match = funcRegex.exec(code)) !== null) {
  const funcName = match[1];
  exportsToWindow += `window.${funcName} = ${funcName};\n`;
}

// Variables that might be accessed by inline JS or other callbacks
exportsToWindow += `
window.navHistory = navHistory;
window.currentUserRole = currentUserRole;
window.userData = userData;
window.db = db;
window.auth = auth;
window.firebase = firebase;
`;

code += exportsToWindow;

fs.writeFileSync('src/scripts/main.js', code, 'utf8');
console.log('main.js converted to ES Module safely.');
