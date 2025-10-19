import {createOrLoadKeys,createOrLoadCSR} from '../keyUtils/CertAndKey.mjs';
import { join } from 'path';

const secureDir = '/secure/cloud/'
const privClientKeyFilePath = join(secureDir, 'keys', 'client.key.pem');
const pubClientKeyFilePath = join(secureDir, 'keys', 'client.key_pub.pem');

// C: 国家代码 (Country)
// ST: 州或省 (State)
// L: 城市 (Locality)
// O: 组织 (Organization)
// OU: 组织单位 (Organizational Unit)
// CN: 通用名称 (Common Name)
const clientSubject = {
  C: 'UN',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Client Certificate for Cloud Connection'
};
const validityYearsClient = 20;

// Certificate Signing Request
const clientCSRFilePath = join(secureDir, 'ssl', 'client.csr');

const clientKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);
console.log('::clientKeyPair:=<', clientKeyPair,'>');

const clientCSR = await createOrLoadCSR(clientCSRFilePath, clientSubject, validityYearsClient,clientKeyPair);
console.log('::clientCSR:=<', clientCSR,'>');
