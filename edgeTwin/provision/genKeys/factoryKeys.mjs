import {createOrLoadKeys,createCertificate} from '../keyUtils/Ed25519Key.mjs';

import { join } from 'path';

const secureDir = '/secure/factory/'

const privRootCAKeyFilePath = join(secureDir, 'keys', 'rootca.priv.key');
const pubRootCAKeyFilePath = join(secureDir, 'keys', 'rootca.pub.key');

const privServerKeyFilePath = join(secureDir, 'keys', 'server.priv.key');
const pubServerKeyFilePath = join(secureDir, 'keys', 'server.pub.key');

const privClientKeyFilePath = join(secureDir, 'keys', 'client.priv.key');
const pubClientKeyFilePath = join(secureDir, 'keys', 'client.pub.key');

const rootCAFilePath = join(secureDir, 'ssl', 'rootca.crt');
const serverCAFilePath = join(secureDir, 'ssl', 'server.crt');
const clientCAFilePath = join(secureDir, 'ssl', 'client.crt');

// C: 国家代码 (Country)
// ST: 州或省 (State)
// L: 城市 (Locality)
// O: 组织 (Organization)
// OU: 组织单位 (Organizational Unit)
// CN: 通用名称 (Common Name)
const rootCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Root CA for Factory Provisioning'
};
const validityYearsRootCA = 20;

const serverCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Server Certificate for Factory Provisioning'
};
const validityYearsServer = 20;

const clientCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Client Certificate for Factory Provisioning'
};
const validityYearsClient = 20;




const rootCAKeyPair = await createOrLoadKeys(privRootCAKeyFilePath, pubRootCAKeyFilePath);
const rootCACert = await createCertificate(rootCAFilePath, rootCASubject, validityYearsRootCA,rootCAKeyPair);
// openssl x509 -in /secure/factory/ssl/rootca.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/rootca.crt



const serverCAKeyPair = await createOrLoadKeys(privServerKeyFilePath, pubServerKeyFilePath);
const serverCACert = await createCertificate(serverCAFilePath, serverCASubject, validityYearsServer,rootCAKeyPair,rootCACert,serverCAKeyPair);

// openssl x509 -in /secure/factory/ssl/server.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/server.crt

const clientCAKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);
const clientCACert = await createCertificate(clientCAFilePath, clientCASubject, validityYearsClient,rootCAKeyPair,rootCACert,clientCAKeyPair);

// openssl x509 -in /secure/factory/ssl/client.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/client.crt
