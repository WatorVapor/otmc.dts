import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import {Ed25519CertificateGenerator} from './Ed25519Ca.mjs';
import path from 'path';
console.log('keyUtils::Global::Ed25519CertificateGenerator:=<', Ed25519CertificateGenerator, '>');

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
    const keyDir = path.dirname(privKeyFilePath);
    if (!existsSync(keyDir)) {
      console.log('密钥目录不存在，开始创建');
      mkdirSync(keyDir, { recursive: true });
      console.log('密钥目录已创建:', keyDir);
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
    const certDir = path.dirname(caFilePath);
    if (!existsSync(certDir)) {
      console.log('证书目录不存在，开始创建');
      mkdirSync(certDir, { recursive: true });
      console.log('证书目录已创建:', certDir);
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

const createCSR = async (csrFilePath, subject, validityYears,subjectKeyPair) => {
  if (!existsSync(csrFilePath)) {
    console.log('未检测到CSR文件，开始生成CSR');
    const csr = await keyGenerator.generateCSR(subject, validityYears,subjectKeyPair);
    console.log('factoryKeys::Global::csr:=<', csr, '>');
    // 确保证书目录存在
    const csrDir = path.dirname(csrFilePath);
    if (!existsSync(csrDir)) {
      console.log('CSR目录不存在，开始创建');
      mkdirSync(csrDir, { recursive: true });
      console.log('CSR目录已创建:', csrDir);
    }
    // 保存CSR
    writeFileSync(csrFilePath, csr.csr);
    console.log('CSR已保存至:', csrFilePath);
    return csr;
  } else {
    console.log('CSR文件已存在，跳过生成');
    return readFileSync(csrFilePath, 'utf8');
  }
}

export { createOrLoadKeys,createCertificate,createCSR };
