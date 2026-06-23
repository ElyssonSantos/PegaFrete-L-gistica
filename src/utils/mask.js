export function maskMoney(i) {
    let v = i.value.replace(/\D/g, "");
    v = (v / 100).toFixed(2) + "";
    v = v.replace(".", ",");
    v = v.replace(/(\d)(\d{3})(\d{3}),/g, "$1.$2.$3,");
    v = v.replace(/(\d)(\d{3}),/g, "$1.$2,");
    i.value = "R$ " + v;
}

export function maskPhone(i) {
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

export function maskCPF(i) {
    let v = i.value.replace(/\D/g, "");
    if (v.length > 11) v = v.slice(0, 11);
    if (v.length === 11) {
        i.value = v.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
    } else {
        i.value = v;
    }
}

export function maskCNPJ(i) {
    let v = i.value.replace(/\D/g, "");
    if (v.length > 14) v = v.slice(0, 14);
    if (v.length === 14) {
        i.value = v.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/, "$1.$2.$3/$4-$5");
    } else {
        i.value = v;
    }
}
