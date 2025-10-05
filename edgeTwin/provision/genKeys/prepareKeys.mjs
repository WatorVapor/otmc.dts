import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import { join } from 'path';
import {Ed25519CertificateGenerator} from '../keyUtils/Ed25519Ca.mjs';
console.log('prepareKeys::Global::Ed25519CertificateGenerator:=<', Ed25519CertificateGenerator, '>');

const factoryDir = '/secure/factory/'
const keyFilePath = join(factoryDir, 'keys');
const privKeyFilePath = join(factoryDir, 'keys', 'device.priv.key');
const pubKeyFilePath = join(factoryDir, 'keys', 'device.pub.key');
const rootCAFilePath = join(factoryDir, 'keys', 'rootca.crt');

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

// 检查密钥和证书文件是否已存在
if (!existsSync(privKeyFilePath)) {
  console.log('未检测到密钥文件，开始生成密钥对');
  const keypari = await keyGenerator.generateKeyPair();
  console.log('prepareKeys::Global::keyPair:=<', keypari, '>');
  // 确保密钥目录存在
  if (!existsSync(keyFilePath)) {
    console.log('密钥目录不存在，开始创建');
    mkdirSync(keyFilePath, { recursive: true });
    console.log('密钥目录已创建:', keyFilePath);
  }

  // 保存私钥
  const pemPrivateKey = await keyGenerator.exportPrivateKeyToPEM(keypari.privateKey);
  console.log('prepareKeys::Global::pemPrivateKey:=<', pemPrivateKey, '>');
  writeFileSync(privKeyFilePath, pemPrivateKey);
  console.log('私钥已保存至:', privKeyFilePath);
  // 保存公钥
  const pemPublicKey = await keyGenerator.exportPublicKeyToPEM(keypari.publicKey);
  console.log('prepareKeys::Global::pemPublicKey:=<', pemPublicKey, '>');
  writeFileSync(pubKeyFilePath, pemPublicKey);
  console.log('公钥已保存至:', pubKeyFilePath);
} else {
  console.log('密钥文件已存在，跳过生成');
  const pemPrivateKey = readFileSync(privKeyFilePath, 'utf8');
  console.log('prepareKeys::Global::pemPrivateKey:=<', pemPrivateKey, '>');
  const privateKey = await keyGenerator.importPrivateKeyFromPEM(pemPrivateKey);
  console.log('prepareKeys::Global::privateKey:=<', privateKey, '>');
}
if (!existsSync(pubKeyFilePath)) {
  const keyPair = await keyGenerator.createPublicKeyFromPrivateKey(privateKey);
  console.log('prepareKeys::Global::keyPair:=<', keyPair, '>');
  // 保存公钥
  const pemPublicKey = await keyGenerator.exportPublicKeyToPEM(keyPair.publicKey);
  console.log('prepareKeys::Global::pemPublicKey:=<', pemPublicKey, '>');
  writeFileSync(pubKeyFilePath, pemPublicKey);
  console.log('公钥已保存至:', pubKeyFilePath);
} else {
  console.log('公钥文件已存在，跳过生成');
  const pemPublicKey = readFileSync(pubKeyFilePath, 'utf8');
  console.log('prepareKeys::Global::pemPublicKey:=<', pemPublicKey, '>');
  const publicKey = await keyGenerator.importPublicKeyFromPEM(pemPublicKey);
  console.log('prepareKeys::Global::publicKey:=<', publicKey, '>');
}
console.log('prepareKeys::Global::keyGenerator:=<', keyGenerator, '>');

if (!existsSync(rootCAFilePath)) {
  console.log('未检测到证书文件，开始生成证书');
  const cert = await keyGenerator.generateRootCA(rootCASubject, validityYearsRootCA);
  console.log('prepareKeys::Global::cert:=<', cert, '>');
  // 确保密钥目录存在
  if (!existsSync(keyFilePath)) {
    console.log('密钥目录不存在，开始创建');
    mkdirSync(keyFilePath, { recursive: true });
    console.log('密钥目录已创建:', keyFilePath);
  }
  // 保存证书
  writeFileSync(rootCAFilePath, cert.certificate);
  console.log('证书已保存至:', rootCAFilePath);
} else {
  console.log('证书文件已存在，跳过生成');
}


