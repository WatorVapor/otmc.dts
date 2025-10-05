import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import { join } from 'path';
import {Ed25519OpenSSL} from '../keyUtils/Ed25519OpenSSL.mjs';
console.log('prepareKeys::Global::Ed25519OpenSSL:=<', Ed25519OpenSSL, '>');

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
const validityYearsRootCA = 50;


const ed25519 = new Ed25519OpenSSL();

const rootCAKeyPair = {
  privateKey: null,
  publicKey: null
};

// 检查密钥和证书文件是否已存在
if (!existsSync(privRootCAKeyFilePath)) {
  console.log('未检测到密钥文件，开始生成密钥对');
  const keyPair = await ed25519.generateKeyPair();
  console.log('prepareKeys::Global::keyPair:=<', keyPair, '>');
  // 确保密钥目录存在
  if (!existsSync(keyFilePath)) {
    console.log('密钥目录不存在，开始创建');
    mkdirSync(keyFilePath, { recursive: true });
    console.log('密钥目录已创建:', keyFilePath);
  }

  // 保存私钥
  writeFileSync(privRootCAKeyFilePath, keyPair.privateKey);
  console.log('私钥已保存至:', privRootCAKeyFilePath);
  // 保存公钥
  writeFileSync(pubRootCAKeyFilePath, keyPair.publicKey);
  console.log('公钥已保存至:', pubRootCAKeyFilePath);
  rootCAKeyPair.publicKey = keyPair.publicKey;
  rootCAKeyPair.privateKey = keyPair.privateKey;
} else {
  console.log('密钥文件已存在，跳过生成');
  rootCAKeyPair.privateKey = readFileSync(privRootCAKeyFilePath).toString('utf-8');
}
if (!existsSync(pubRootCAKeyFilePath)) {
  const keyPair = await ed25519.createPublicKeyFromPrivateKey(keyPair.privateKey);
  console.log('prepareKeys::Global::keyPair:=<', keyPair, '>');
  // 保存公钥
  writeFileSync(pubRootCAKeyFilePath, keyPair.publicKey);
  console.log('公钥已保存至:', pubRootCAKeyFilePath);
} else {
  console.log('公钥文件已存在，跳过生成');
  rootCAKeyPair.publicKey = readFileSync(pubRootCAKeyFilePath).toString('utf-8');
}
console.log('prepareKeys::Global::ed25519:=<', ed25519, '>');

if (!existsSync(rootCAFilePath)) {
  console.log('未检测到证书文件，开始生成证书');
  const cert = await ed25519.generateRootCA(rootCASubject, validityYearsRootCA,rootCAKeyPair.publicKey,rootCAKeyPair.privateKey);
  console.log('prepareKeys::Global::cert:=<', cert, '>');
  // 确保密钥目录存在
  if (!existsSync(sslFilePath)) {
    console.log('密钥目录不存在，开始创建');
    mkdirSync(sslFilePath, { recursive: true });
    console.log('密钥目录已创建:', sslFilePath);
  }
  // 保存证书
  writeFileSync(rootCAFilePath, cert.certificate);
  console.log('证书已保存至:', rootCAFilePath);
} else {
  console.log('证书文件已存在，跳过生成');
}


