import {createOrLoadKeys,createCSR} from '../keyUtils/Ed25519Key.mjs';
import { join } from 'path';

const secureDir = '/secure/cloud/'
const privClientKeyFilePath = join(secureDir, 'keys', 'client.priv.key');
const pubClientKeyFilePath = join(secureDir, 'keys', 'client.pub.key');

// C: 国家代码 (Country)
// ST: 州或省 (State)
// L: 城市 (Locality)
// O: 组织 (Organization)
// OU: 组织单位 (Organizational Unit)
// CN: 通用名称 (Common Name)
const clientCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Client Certificate for Cloud Connection'
};
const validityYearsClientCA = 20;

// Certificate Signing Request
const clientCSRFilePath = join(secureDir, 'ssl', 'client.csr');

const clientCAKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);

const clientCSR = await createCSR(clientCSRFilePath, clientCASubject, validityYearsClientCA,clientCAKeyPair);
