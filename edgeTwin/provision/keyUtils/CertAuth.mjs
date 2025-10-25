import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import OpenSSLCA from './ECDSAOpenSSLCa.mjs';

import path from 'path';

const signCSR = (csrPem,validityYears,issueKey,issueCert) => {
    const openSSLCA = new OpenSSLCA();
    return openSSLCA.createCert4CSR(csrPem,validityYears,issueKey,issueCert);
}


export { signCSR };
