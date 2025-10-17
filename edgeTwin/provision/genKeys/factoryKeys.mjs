import {createOrLoadKeys,createCertificate} from '../keyUtils/CertAndKey.mjs';

import { join } from 'path';

const secureDir = '/secure/factory/'

const privRootCAKeyFilePath = join(secureDir, 'keys', 'root.key.pem');
const pubRootCAKeyFilePath = join(secureDir, 'keys', 'root.key_pub.pem');

const privServerKeyFilePath = join(secureDir, 'keys', 'server.key.pem');
const pubServerKeyFilePath = join(secureDir, 'keys', 'server.key_pub.pem');

const privClientKeyFilePath = join(secureDir, 'keys', 'client.key.pem');
const pubClientKeyFilePath = join(secureDir, 'keys', 'client.key_pub.pem');

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
  C: 'UN',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Root CA for Factory Provisioning'
};
const validityYearsRootCA = 20;

const serverCASubject = {
  C: 'UN',
  ST: 'wator',
  L: 'otmc',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Server Certificate for Factory Provisioning'
};
const validityYearsServer = 20;

const clientCASubject = {
  C: 'UN',
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



const serverKeyPair = await createOrLoadKeys(privServerKeyFilePath, pubServerKeyFilePath);
const serverCACert = await createCertificate(serverCAFilePath, serverCASubject, validityYearsServer,rootCAKeyPair,rootCACert,serverKeyPair);

// openssl x509 -in /secure/factory/ssl/server.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/server.crt

const clientKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);
const clientCACert = await createCertificate(clientCAFilePath, clientCASubject, validityYearsClient,rootCAKeyPair,rootCACert,clientKeyPair);

// openssl x509 -in /secure/factory/ssl/client.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/client.crt
