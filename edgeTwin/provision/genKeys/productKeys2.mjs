import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import { join } from 'path';
import {Ed25519CertificateGenerator} from '../keyUtils/Ed25519Ca.mjs';
console.log('prepareKeys::Global::Ed25519CertificateGenerator:=<', Ed25519CertificateGenerator, '>');

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


const keyGenerator = new Ed25519CertificateGenerator();

const rootCAKeyPair = {
  privateKey: null,
  publicKey: null
};

// 检查密钥和证书文件是否已存在
if (!existsSync(privRootCAKeyFilePath)) {
  console.log('未检测到密钥文件，开始生成密钥对');
  const keypari = await keyGenerator.generateKeyPair();
  console.log('productKeys2::Global::keyPair:=<', keypari, '>');
  // 确保密钥目录存在
  if (!existsSync(keyFilePath)) {
    console.log('密钥目录不存在，开始创建');
    mkdirSync(keyFilePath, { recursive: true });
    console.log('密钥目录已创建:', keyFilePath);
  }
  rootCAKeyPair.privateKey = keypari.privateKey;
  rootCAKeyPair.publicKey = keypari.publicKey;

  // 保存私钥
  const pemPrivateKey = await keyGenerator.exportPrivateKeyToPEM(keypari.privateKey);
  console.log('productKeys2::Global::pemPrivateKey:=<', pemPrivateKey, '>');
  writeFileSync(privRootCAKeyFilePath, pemPrivateKey);
  console.log('私钥已保存至:', privRootCAKeyFilePath);
  // 保存公钥
  const pemPublicKey = await keyGenerator.exportPublicKeyToPEM(keypari.publicKey);
  console.log('productKeys2::Global::pemPublicKey:=<', pemPublicKey, '>');
  writeFileSync(pubRootCAKeyFilePath, pemPublicKey);
  console.log('公钥已保存至:', pubRootCAKeyFilePath);
} else {
  console.log('密钥文件已存在，跳过生成');
  const pemPrivateKey = readFileSync(privRootCAKeyFilePath, 'utf8');
  console.log('productKeys2::Global::pemPrivateKey:=<', pemPrivateKey, '>');
  const privateKey = await keyGenerator.importPrivateKeyFromPEM(pemPrivateKey);
  console.log('productKeys2::Global::privateKey:=<', privateKey, '>');
  rootCAKeyPair.privateKey = privateKey;
}
if (!existsSync(pubRootCAKeyFilePath)) {
  const keyPair = await keyGenerator.createPublicKeyFromPrivateKey(privateKey);
  console.log('productKeys2::Global::keyPair:=<', keyPair, '>');
  // 保存公钥
  const pemPublicKey = await keyGenerator.exportPublicKeyToPEM(keyPair.publicKey);
  console.log('productKeys2::Global::pemPublicKey:=<', pemPublicKey, '>');
  writeFileSync(pubRootCAKeyFilePath, pemPublicKey);
  console.log('公钥已保存至:', pubRootCAKeyFilePath);
} else {
  console.log('公钥文件已存在，跳过生成');
  const pemPublicKey = readFileSync(pubRootCAKeyFilePath, 'utf8');
  console.log('productKeys2::Global::pemPublicKey:=<', pemPublicKey, '>');
  rootCAKeyPair.publicKey = await keyGenerator.importPublicKeyFromPEM(pemPublicKey);
  console.log('productKeys2::Global::publicKey:=<', rootCAKeyPair.publicKey, '>');
}
console.log('productKeys2::Global::keyGenerator:=<', keyGenerator, '>');

if (!existsSync(rootCAFilePath)) {
  console.log('未检测到证书文件，开始生成证书');
  const cert = await keyGenerator.generateRootCA(rootCASubject, validityYearsRootCA, rootCAKeyPair);
  console.log('productKeys2::Global::cert:=<', cert, '>');
  // 确保证书目录存在
  if (!existsSync(sslFilePath)) {
    console.log('证书目录不存在，开始创建');
    mkdirSync(sslFilePath, { recursive: true });
    console.log('证书目录已创建:', sslFilePath);
  }
  // 保存证书
  writeFileSync(rootCAFilePath, cert.certificate);
  console.log('证书已保存至:', rootCAFilePath);
} else {
  console.log('证书文件已存在，跳过生成');
}


