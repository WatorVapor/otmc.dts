import { existsSync, mkdirSync,readFileSync } from 'fs';
import path from 'path';
import os from 'os';
import net from 'net';
import OpenSSLCA from './ECDSAOpenSSLCa.mjs';

//console.log('keyUtils::Global::OpenSSLCA:=<', OpenSSLCA, '>');

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
    const csr = await keyGenerator.createServerCSR(csrFilePath,subject, validityYears,subjectKeyPair.privateKey, defaultSAN);
    console.log('factoryKeys::Global::csr:=<', csr, '>');
    console.log('CSR已保存至:', csrFilePath);
    return csr;
  } else {
    console.log('CSR文件已存在，跳过生成');
    return readFileSync(csrFilePath, 'utf8');
  }
}

export { createOrLoadKeys,createOrLoadCertificate,createOrLoadCSR };



// @description: 判断IP是否为私有IP
// @param {string} ip - IP地址
// @return {boolean} - 是否为私有IP
const isPrivateIP = (ip) =>{
  if (!net.isIP(ip)) return false;
  // IPv4 判断
  if (net.isIPv4(ip)) {
    return (
      ip.startsWith('10.') || // 10.0.0.0/8
      ip.startsWith('192.168.') || // 192.168.0.0/16
      ip.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./) || // 172.16.0.0 – 172.31.255.255
      ip === '127.0.0.1' // loopback
    );
  }

  // IPv6 判断
  if (net.isIPv6(ip)) {
    return (
      ip === '::1' || // loopback
      ip.startsWith('fc') || // fc00::/7 unique local address
      ip.startsWith('fd') || // fd00::/8 unique local address
      ip.startsWith('fe80') // link-local address
    );
  }
  return false;
}

const getDefaultAltNames = () => {
  const networkInterfaces = os.networkInterfaces();
  const names = [
    { type: 'DNS', value: 'localhost' }
  ];

  for (const interfaceName in networkInterfaces) {
    const interfaceAddresses = networkInterfaces[interfaceName];
    for (const addressInfo of interfaceAddresses) {
      console.log('addressInfo:=<', addressInfo, '>');
      if(isPrivateIP(addressInfo.address)){
        names.push({ type: 'IP', value: addressInfo.address });
      }
    }
  }
  //console.log('names:=<', names, '>');
  return names;
};

const defaultSAN = {
  critical: false,
  names: getDefaultAltNames()
};


