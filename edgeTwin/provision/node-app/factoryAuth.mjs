import { join } from 'path';
import {createOrLoadKeys} from '../keyUtils/CertAndKey.mjs';
import {signCSR} from '../keyUtils/CertAuth.mjs';
const secureDir = '/secure/factory/'
const validityYearsClient = 1;

const readCsrPem = (req,onCSR) => {
    let csrText = '';
    req.setEncoding('utf8');
    req.on('data', chunk => csrText += chunk);
    req.on('end', () => {
        console.log('readCsrPem::csrText:=<', csrText, '>');
        onCSR(csrText);
    });
}

const issueClientCertFactory = (req,res) => {
    readCsrPem(req,csrPem => {
        issueCSRFactory(csrPem,res);
    });
}
const issueCSRFactory = (csrPem,res) => {
    console.log('issueCSRFactory::csrPem:=<', csrPem, '>');
    console.log('issueCSRFactory::rootCAKeyPair:=<', rootCAKeyPair,'>');
    const outCert = signCSR(csrPem,validityYearsClient,rootCAKeyPair.privateKey,rootCAFilePath);
    console.log('issueCSRFactory::outCert:=<', outCert, '>');
    const response = {
        certificate: outCert.certificate,
        result: 'success'
    };
    res.status(200).send(JSON.stringify(response));
}

const privRootCAKeyFilePath = join(secureDir, 'keys', 'root.key.pem');
const pubRootCAKeyFilePath = join(secureDir, 'keys', 'root.key_pub.pem');
const rootCAFilePath = join(secureDir, 'ssl', 'rootca.crt');

const rootCAKeyPair = await createOrLoadKeys(privRootCAKeyFilePath, pubRootCAKeyFilePath);
console.log('::rootCAKeyPair:=<', rootCAKeyPair,'>');


export { issueClientCertFactory };
