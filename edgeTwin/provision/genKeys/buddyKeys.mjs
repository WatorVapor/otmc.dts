import {createOrLoadKeys,createCertificate} from '../keyUtils/Ed25519Key.mjs';

import { join } from 'path';

const secureDir = '/secure/buddy/'

const privRootCAKeyFilePath = join(secureDir, 'keys', 'rootca.priv.key');
const pubRootCAKeyFilePath = join(secureDir, 'keys', 'rootca.pub.key');

const privServerKeyFilePath = join(secureDir, 'keys', 'server.priv.key');
const pubServerKeyFilePath = join(secureDir, 'keys', 'server.pub.key');

const privClientKeyFilePath = join(secureDir, 'keys', 'client.priv.key');
const pubClientKeyFilePath = join(secureDir, 'keys', 'client.pub.key');

const rootCAFilePath = join(secureDir, 'ssl', 'rootca.crt');
const serverCAFilePath = join(secureDir, 'ssl', 'server.crt');
const clientCAFilePath = join(secureDir, 'ssl', 'client.crt');



const rootCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'wator',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Root CA for Cluster Provisioning'
};
const validityYearsRootCA = 20;

const serverCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'wator',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Server CA for Cluster Provisioning'
};
const validityYearsServerCA = 20;

const clientCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'wator',
  O: 'otmc',
  OU: 'dts',
  CN: 'Digital Twin Client CA for Cluster Provisioning'
};
const validityYearsClientCA = 20;




const rootCAKeyPair = await createOrLoadKeys(privRootCAKeyFilePath, pubRootCAKeyFilePath);
const rootCACert = await createCertificate(rootCAFilePath, rootCASubject, validityYearsRootCA,rootCAKeyPair);
// openssl x509 -in /secure/cluster/ssl/rootca.crt -noout -text
// openssl verify -CAfile /secure/cluster/ssl/rootca.crt /secure/cluster/ssl/rootca.crt



const serverCAKeyPair = await createOrLoadKeys(privServerKeyFilePath, pubServerKeyFilePath);
const serverCACert = await createCertificate(serverCAFilePath, serverCASubject, validityYearsServerCA,rootCAKeyPair,rootCACert,serverCAKeyPair);

// openssl x509 -in /secure/cluster/ssl/server.crt -noout -text
// openssl verify -CAfile /secure/cluster/ssl/rootca.crt /secure/cluster/ssl/server.crt

const clientCAKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);
const clientCACert = await createCertificate(clientCAFilePath, clientCASubject, validityYearsClientCA,rootCAKeyPair,rootCACert,clientCAKeyPair);

// openssl x509 -in /secure/cluster/ssl/client.crt -noout -text
// openssl verify -CAfile /secure/cluster/ssl/rootca.crt /secure/cluster/ssl/client-sample.crt
