import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import { join } from 'path';
import {Ed25519CertificateGenerator} from '../keyUtils/Ed25519Ca.mjs';
console.log('factoryKeys::Global::Ed25519CertificateGenerator:=<', Ed25519CertificateGenerator, '>');

const factoryDir = '/secure/factory/'
const keyFilePath = join(factoryDir, 'keys');

const privRootCAKeyFilePath = join(factoryDir, 'keys', 'rootca.priv.key');
const pubRootCAKeyFilePath = join(factoryDir, 'keys', 'rootca.pub.key');

const privServerKeyFilePath = join(factoryDir, 'keys', 'server.priv.key');
const pubServerKeyFilePath = join(factoryDir, 'keys', 'server.pub.key');

const privClientKeyFilePath = join(factoryDir, 'keys', 'client.priv.key');
const pubClientKeyFilePath = join(factoryDir, 'keys', 'client.pub.key');

const sslFilePath = join(factoryDir, 'ssl');
const rootCAFilePath = join(factoryDir, 'ssl', 'rootca.crt');
const serverCAFilePath = join(factoryDir, 'ssl', 'server.crt');
const clientCAFilePath = join(factoryDir, 'ssl', 'client.crt');


const rootCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'wator',
  O: 'dts',
  OU: 'dts sample',
  CN: 'Digital Twin Root CA for Factory Provisioning'
};
const validityYearsRootCA = 20;

const serverCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'wator',
  O: 'dts',
  OU: 'dts sample',
  CN: 'Digital Twin Server CA for Factory Provisioning'
};
const validityYearsServerCA = 20;

const clientCASubject = {
  C: 'xyz',
  ST: 'wator',
  L: 'wator',
  O: 'dts',
  OU: 'dts sample',
  CN: 'Digital Twin Client CA for Factory Provisioning'
};
const validityYearsClientCA = 20;



const keyGenerator = new Ed25519CertificateGenerator();



const createOrLoadKeys = async (privKeyFilePath, pubKeyFilePath) => {
  const retKeyPair = {
    privateKey: null,
    publicKey: null
  };
  // 检查密钥和证书文件是否已存在
  if (!existsSync(privKeyFilePath)) {
    console.log('未检测到密钥文件，开始生成密钥对');
    const keypari = await keyGenerator.generateKeyPair();
    console.log('factoryKeys::Global::keyPair:=<', keypari, '>');
    // 确保密钥目录存在
    if (!existsSync(keyFilePath)) {
      console.log('密钥目录不存在，开始创建');
      mkdirSync(keyFilePath, { recursive: true });
      console.log('密钥目录已创建:', keyFilePath);
    }
    retKeyPair.privateKey = keypari.privateKey;
    retKeyPair.publicKey = keypari.publicKey;

    // 保存私钥
    const pemPrivateKey = await keyGenerator.exportPrivateKeyToPEM(keypari.privateKey);
    console.log('factoryKeys::Global::pemPrivateKey:=<', pemPrivateKey, '>');
    writeFileSync(privKeyFilePath, pemPrivateKey);
    console.log('私钥已保存至:', privKeyFilePath);
    // 保存公钥
    const pemPublicKey = await keyGenerator.exportPublicKeyToPEM(keypari.publicKey);
    console.log('factoryKeys::Global::pemPublicKey:=<', pemPublicKey, '>');
    writeFileSync(pubKeyFilePath, pemPublicKey);
    console.log('公钥已保存至:', pubKeyFilePath);
  } else {
    console.log('密钥文件已存在，跳过生成');
    const pemPrivateKey = readFileSync(privKeyFilePath, 'utf8');
    console.log('factoryKeys::Global::pemPrivateKey:=<', pemPrivateKey, '>');
    const privateKey = await keyGenerator.importPrivateKeyFromPEM(pemPrivateKey);
    console.log('factoryKeys::Global::privateKey:=<', privateKey, '>');
    retKeyPair.privateKey = privateKey;
  }
  if (!existsSync(pubKeyFilePath)) {
    const keyPair = await keyGenerator.createPublicKeyFromPrivateKey(privateKey);
    console.log('factoryKeys::Global::keyPair:=<', keyPair, '>');
    // 保存公钥
    const pemPublicKey = await keyGenerator.exportPublicKeyToPEM(keyPair.publicKey);
    console.log('factoryKeys::Global::pemPublicKey:=<', pemPublicKey, '>');
    writeFileSync(pubKeyFilePath, pemPublicKey);
    console.log('公钥已保存至:', pubKeyFilePath);
  } else {
    console.log('公钥文件已存在，跳过生成');
    const pemPublicKey = readFileSync(pubKeyFilePath, 'utf8');
    console.log('factoryKeys::Global::pemPublicKey:=<', pemPublicKey, '>');
    retKeyPair.publicKey = await keyGenerator.importPublicKeyFromPEM(pemPublicKey);
    console.log('factoryKeys::Global::publicKey:=<', retKeyPair.publicKey, '>');
  }
  console.log('factoryKeys::Global::keyGenerator:=<', keyGenerator, '>');
  return retKeyPair;
}
const createCertificate = async (caFilePath, subject, validityYears,issuerKeyPair,issuerCert = null,subjectKeyPair = null) => {
  if (!existsSync(caFilePath)) {
    console.log('未检测到证书文件，开始生成证书');
    let cert = false;
    if(subjectKeyPair === null && issuerCert === null){
      cert = await keyGenerator.generateRootCA(subject, validityYears, issuerKeyPair);
    } else {
      cert = await keyGenerator.generateLeafCertificate(subject, validityYears, issuerKeyPair,issuerCert,subjectKeyPair);
    }
    console.log('factoryKeys::Global::cert:=<', cert, '>');
    // 确保证书目录存在
    if (!existsSync(sslFilePath)) {
      console.log('证书目录不存在，开始创建');
      mkdirSync(sslFilePath, { recursive: true });
      console.log('证书目录已创建:', sslFilePath);
    }
    // 保存证书
    writeFileSync(caFilePath, cert.certificate);
    console.log('证书已保存至:', caFilePath);
    return cert.certificate;
  } else {
    console.log('证书文件已存在，跳过生成');
    return readFileSync(caFilePath, 'utf8');
  }
}

const rootCAKeyPair = await createOrLoadKeys(privRootCAKeyFilePath, pubRootCAKeyFilePath);
const rootCACert = await createCertificate(rootCAFilePath, rootCASubject, validityYearsRootCA,rootCAKeyPair);
// openssl x509 -in /secure/factory/ssl/rootca.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/rootca.crt



const serverCAKeyPair = await createOrLoadKeys(privServerKeyFilePath, pubServerKeyFilePath);
const serverCACert = await createCertificate(serverCAFilePath, serverCASubject, validityYearsServerCA,rootCAKeyPair,rootCACert,serverCAKeyPair);

// openssl x509 -in /secure/factory/ssl/server.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/server.crt

const clientCAKeyPair = await createOrLoadKeys(privClientKeyFilePath, pubClientKeyFilePath);
const clientCACert = await createCertificate(clientCAFilePath, clientCASubject, validityYearsClientCA,rootCAKeyPair,rootCACert,clientCAKeyPair);

// openssl x509 -in /secure/factory/ssl/client.crt -noout -text
// openssl verify -CAfile /secure/factory/ssl/rootca.crt /secure/factory/ssl/client.crt
