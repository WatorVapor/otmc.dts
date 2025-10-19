import { existsSync, writeFileSync,mkdirSync,readFileSync } from 'fs';
import OpenSSLCA from './ECDSAOpenSSLCa.mjs';

import path from 'path';
console.log('keyUtils::Global::OpenSSLCA:=<', OpenSSLCA, '>');

const keyGenerator = new OpenSSLCA();



const createOrLoadKeys = async (privKeyFilePath, pubKeyFilePath) => {
  const retKeyPair = {
    privateKey: null,
    publicKey: null
  };
  // 检查密钥和证书文件是否已存在
  if (!existsSync(privKeyFilePath)) {
    console.log('未检测到密钥文件，开始生成密钥对');
    // 确保密钥目录存在
    const keyDir = path.dirname(privKeyFilePath);
    if (!existsSync(keyDir)) {
      console.log('密钥目录不存在，开始创建');
      mkdirSync(keyDir, { recursive: true });
      console.log('密钥目录已创建:', keyDir);
    }
    const keypari = keyGenerator.generateECDSAKeyPair(privKeyFilePath);
    console.log('factoryKeys::Global::keyPair:=<', keypari, '>');
    retKeyPair.privateKey = keypari.privateKey;
    retKeyPair.publicKey = keypari.publicKey;

  } else {
    console.log('密钥文件已存在，跳过生成');
    retKeyPair.privateKey = privKeyFilePath;
  }
  if (!existsSync(pubKeyFilePath)) {
    const keyPair = keyGenerator.createPublicKeyFromPrivateKey(privKeyFilePath,pubKeyFilePath);
    console.log('factoryKeys::Global::keyPair:=<', keyPair, '>');
    console.log('公钥已保存至:', pubKeyFilePath);
  } else {
    console.log('公钥文件已存在，跳过生成');
    retKeyPair.publicKey = pubKeyFilePath;
  }
  console.log('factoryKeys::Global::keyGenerator:=<', keyGenerator, '>');
  return retKeyPair;
}
const createOrLoadCertificate = async (caFilePath, subject, validityYears,subjectKeyPair,issuerCert = null,issuerKeyPair = null) => {
  if (!existsSync(caFilePath)) {
    console.log('未检测到证书文件，开始生成证书');
    let cert = false;
    const defaultSAN = {
      critical: false,
      names: [
        { type: 'dns', value: 'localhost' },
        { type: 'ip', value: '127.0.0.1' },
        { type: 'ip', value: '::1' }
      ]
    };

    // 确保证书目录存在
    const certDir = path.dirname(caFilePath);
    if (!existsSync(certDir)) {
      console.log('证书目录不存在，开始创建');
      mkdirSync(certDir, { recursive: true });
      console.log('证书目录已创建:', certDir);
    }
    
    if(issuerKeyPair === null && issuerCert === null){
      cert = keyGenerator.createRootCA(caFilePath,subject, validityYears,subjectKeyPair.privateKey,defaultSAN);
    } else {
      cert = keyGenerator.createServerCert(caFilePath,subject,validityYears,subjectKeyPair.privateKey,issuerKeyPair.privateKey,issuerCert,defaultSAN);
    }
    console.log('factoryKeys::Global::cert:=<', cert, '>');
    return cert.certificate;
  } else {
    console.log('证书文件已存在，跳过生成');
    return readFileSync(caFilePath, 'utf8');
  }
}

const createOrLoadCSR = async (csrFilePath, subject, validityYears,subjectKeyPair) => {
  if (!existsSync(csrFilePath)) {
    console.log('未检测到CSR文件，开始生成CSR');
    // 确保证书目录存在
    const csrDir = path.dirname(csrFilePath);
    if (!existsSync(csrDir)) {
      console.log('CSR目录不存在，开始创建');
      mkdirSync(csrDir, { recursive: true });
      console.log('CSR目录已创建:', csrDir);
    }
    const csr = await keyGenerator.createServerCSR(csrFilePath,subject, validityYears,subjectKeyPair.privateKey);
    console.log('factoryKeys::Global::csr:=<', csr, '>');
    console.log('CSR已保存至:', csrFilePath);
    return csr;
  } else {
    console.log('CSR文件已存在，跳过生成');
    return readFileSync(csrFilePath, 'utf8');
  }
}

export { createOrLoadKeys,createOrLoadCertificate,createOrLoadCSR };
