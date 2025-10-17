// ECDSACertificateGenerator-forge.js
import forge from 'node-forge';
import { webcrypto } from 'crypto';
const { subtle } = webcrypto;



/**
 * 基于 node-forge 的 ECDSA 证书生成器
 * 支持浏览器和 Node.js 环境
 */
class ECDSACertificateGenerator {
  constructor() {
    // 支持的曲线配置
    this.curves = {
      'P-256': 'secp256r1',
      'P-384': 'secp384r1', 
      'P-521': 'secp521r1'
    };
    
    this.curveName = 'P-384'; // 默认曲线
    this.keyPair = null;
    this.privateKeyPEM = null;
    this.publicKeyPEM = null;
  }

  /**
   * 设置椭圆曲线
   */
  setCurve(curveName) {
    if (!this.curves[curveName]) {
      throw new Error(`不支持的曲线: ${curveName}. 支持: ${Object.keys(this.curves).join(', ')}`);
    }
    this.curveName = curveName;
    return this;
  }
  /**
   * 生成 ECDSA 密钥对
   */
  async generateKeyPair() {
    try {
      const keyPair = await subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: this.curveName,
        },
        true,
        ['sign', 'verify']
      );
      
      this.keyPair = keyPair;
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
      
      // 自动导出 PEM 格式
      this.privateKeyPEM = await this.exportPrivateKeyToPEM(keyPair.privateKey);
      this.publicKeyPEM = await this.exportPublicKeyToPEM(keyPair.publicKey);
      
      return keyPair;
    } catch (error) {
      throw new Error(`生成密钥对时出错: ${error.message}`);
    }
  }

  /**
   * 从 PEM 导入私钥
   */
  async importPrivateKeyFromPEM(pem) {
    try {
      this.privateKeyPEM = pem;
      const privateKey = forge.pki.privateKeyFromPem(pem);
      
      if (!this.keyPair) {
        this.keyPair = {};
      }
      this.keyPair.privateKey = privateKey;
      
      return privateKey;
    } catch (error) {
      throw new Error(`导入私钥时出错: ${error.message}`);
    }
  }

  /**
   * 从 PEM 导入公钥
   */
  async importPublicKeyFromPEM(pem) {
    try {
      this.publicKeyPEM = pem;
      const publicKey = forge.pki.publicKeyFromPem(pem);
      
      if (!this.keyPair) {
        this.keyPair = {};
      }
      this.keyPair.publicKey = publicKey;
      
      return publicKey;
    } catch (error) {
      throw new Error(`导入公钥时出错: ${error.message}`);
    }
  }

  /**
   * 创建证书属性数组
   */
  createAttributes(subject) {
    const attrs = [];
    
    if (subject.C) attrs.push({ name: 'countryName', value: subject.C });
    if (subject.ST) attrs.push({ name: 'stateOrProvinceName', value: subject.ST });
    if (subject.L) attrs.push({ name: 'localityName', value: subject.L });
    if (subject.O) attrs.push({ name: 'organizationName', value: subject.O });
    if (subject.OU) attrs.push({ name: 'organizationalUnitName', value: subject.OU });
    if (subject.CN) attrs.push({ name: 'commonName', value: subject.CN });
    if (subject.EMAIL) attrs.push({ name: 'emailAddress', value: subject.EMAIL });
    
    return attrs;
  }

  /**
   * 创建证书扩展
   */
  createExtensions(extensionsConfig, isCA = false) {
    const extensions = [];
    
    // 基本约束
    if (extensionsConfig.basicConstraints) {
      const config = extensionsConfig.basicConstraints;
      extensions.push({
        name: 'basicConstraints',
        critical: config.critical !== undefined ? config.critical : true,
        cA: isCA,
        pathLenConstraint: config.pathLenConstraint
      });
    }
    
    // 密钥用法
    if (extensionsConfig.keyUsage) {
      const config = extensionsConfig.keyUsage;
      extensions.push({
        name: 'keyUsage',
        critical: config.critical !== undefined ? config.critical : true,
        digitalSignature: config.usage.includes('digitalSignature'),
        nonRepudiation: config.usage.includes('nonRepudiation'),
        keyEncipherment: config.usage.includes('keyEncipherment'),
        dataEncipherment: config.usage.includes('dataEncipherment'),
        keyAgreement: config.usage.includes('keyAgreement'),
        keyCertSign: config.usage.includes('keyCertSign'),
        cRLSign: config.usage.includes('cRLSign'),
        encipherOnly: config.usage.includes('encipherOnly'),
        decipherOnly: config.usage.includes('decipherOnly')
      });
    }
    
    // 扩展密钥用法
    if (extensionsConfig.extendedKeyUsage) {
      const config = extensionsConfig.extendedKeyUsage;
      const extKeyUsage = [];
      
      if (config.usage.includes('serverAuth')) extKeyUsage.push('serverAuth');
      if (config.usage.includes('clientAuth')) extKeyUsage.push('clientAuth');
      if (config.usage.includes('codeSigning')) extKeyUsage.push('codeSigning');
      if (config.usage.includes('emailProtection')) extKeyUsage.push('emailProtection');
      if (config.usage.includes('timeStamping')) extKeyUsage.push('timeStamping');
      if (config.usage.includes('ocspSigning')) extKeyUsage.push('ocspSigning');
      
      extensions.push({
        name: 'extKeyUsage',
        critical: config.critical !== undefined ? config.critical : true,
        serverAuth: config.usage.includes('serverAuth'),
        clientAuth: config.usage.includes('clientAuth'),
        codeSigning: config.usage.includes('codeSigning'),
        emailProtection: config.usage.includes('emailProtection'),
        timeStamping: config.usage.includes('timeStamping'),
        ocspSigning: config.usage.includes('ocspSigning')
      });
    }
    
    // 主题备用名称 (SAN) - 修复关键部分
    if (extensionsConfig.subjectAltName) {
      const config = extensionsConfig.subjectAltName;
      const altNames = [];
      
      if (config.names && Array.isArray(config.names)) {
        config.names.forEach(name => {
          if (name.type === 'dns') {
            altNames.push({ type: 2, value: name.value }); // DNS
          } else if (name.type === 'ip') {
            altNames.push({ type: 7, ip: name.value }); // IP
          } else if (name.type === 'email') {
            altNames.push({ type: 1, value: name.value }); // Email
          }
        });
      }
      
      if (altNames.length > 0) {
        extensions.push({
          name: 'subjectAltName',
          critical: config.critical !== undefined ? config.critical : false,
          altNames: altNames
        });
      }
    }
    
    return extensions;
  }

  /**
   * 生成证书
   */
  async generateCertificate(params) {
    try {
      const {
        subjectKeyPair,
        issuerKeyPair,
        subject,
        issuer,
        serialNumber = this.generateSerialNumber(),
        validityDays = 365,
        extensions = {}
      } = params;
      
      // 创建证书对象:cite[3]
      const cert = forge.pki.createCertificate();
      
      // 设置证书字段
      cert.publicKey = subjectKeyPair.publicKey || subjectKeyPair;
      cert.serialNumber = serialNumber;
      
      // 设置有效期
      const now = new Date();
      cert.validity.notBefore = now;
      cert.validity.notAfter = new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000);
      
      // 设置主题和颁发者
      cert.setSubject(this.createAttributes(subject));
      cert.setIssuer(this.createAttributes(issuer));
      
      // 设置扩展
      const isCA = extensions.basicConstraints && extensions.basicConstraints.isCA;
      const certExtensions = this.createExtensions(extensions, isCA);
      cert.setExtensions(certExtensions);
      
      // 使用颁发者私钥签名证书:cite[3]
      const issuerPrivateKey = issuerKeyPair.privateKey || issuerKeyPair;
      cert.sign(issuerPrivateKey, forge.md.sha256.create());
      
      // 转换为 PEM 格式
      const certificatePEM = forge.pki.certificateToPem(cert);
      
      return certificatePEM;
      
    } catch (error) {
      throw new Error(`生成证书时出错: ${error.message}`);
    }
  }

  /**
   * 生成随机序列号
   */
  generateSerialNumber() {
    // 生成 16 字节随机序列号
    const bytes = forge.random.getBytesSync(16);
    return forge.util.bytesToHex(bytes);
  }

  /**
   * 生成根 CA 证书
   */
  async generateRootCA(subject, validityYears = 10, keyPair = null) {
    try {
      if (!keyPair) {
        keyPair = await this.generateKeyPair();
      }
      
      console.log(`正在生成 ${this.curveName} 根 CA 证书...`);
      
      const certificate = await this.generateCertificate({
        subjectKeyPair: keyPair,
        issuerKeyPair: keyPair,
        subject: subject,
        issuer: subject,
        validityDays: validityYears * 365,
        extensions: {
          basicConstraints: {
            critical: true,
            isCA: true,
            pathLenConstraint: 1
          },
          keyUsage: {
            critical: true,
            usage: ['keyCertSign', 'cRLSign', 'digitalSignature']
          }
        }
      });
      
      console.log('✓ 根 CA 生成成功');
      return {
        keyPair: keyPair,
        certificate,
        privateKeyPEM: this.privateKeyPEM,
        publicKeyPEM: this.publicKeyPEM
      };
      
    } catch (error) {
      throw new Error(`生成根 CA 时出错: ${error.message}`);
    }
  }

  /**
   * 生成服务器证书（包含正确的 SAN 扩展）
   */
  async generateServerCertificate(subject, validityDays = 365, issuerKeyPair, issuerSubject, subjectKeyPair = null, sanConfig = null) {
    try {
      if (!subjectKeyPair) {
        subjectKeyPair = await this.generateKeyPair();
      }
      
      console.log(`正在生成 ${this.curveName} 服务器证书...`);
      
      // 默认 SAN 配置
      const defaultSAN = {
        critical: false,
        names: [
          { type: 'dns', value: 'localhost' },
          { type: 'ip', value: '127.0.0.1' },
          { type: 'ip', value: '::1' }
        ]
      };
      
      const certificate = await this.generateCertificate({
        subjectKeyPair: subjectKeyPair,
        issuerKeyPair: issuerKeyPair,
        subject: subject,
        issuer: issuerSubject,
        validityDays: validityDays,
        extensions: {
          basicConstraints: {
            critical: true,
            isCA: false
          },
          keyUsage: {
            critical: true,
            usage: ['digitalSignature', 'keyEncipherment', 'keyAgreement']
          },
          extendedKeyUsage: {
            critical: true,
            usage: ['serverAuth', 'clientAuth']
          },
          subjectAltName: sanConfig || defaultSAN
        }
      });
      
      console.log('✓ 服务器证书生成成功');
      return {
        certificate,
        keyPair: subjectKeyPair,
        privateKeyPEM: await this.exportPrivateKeyToPEM(subjectKeyPair.privateKey),
        publicKeyPEM: await this.exportPublicKeyToPEM(subjectKeyPair.publicKey)
      };
      
    } catch (error) {
      throw new Error(`生成服务器证书时出错: ${error.message}`);
    }
  }

  /**
   * 导出私钥为 PEM 格式
   */
  async exportPrivateKeyToPEM(privateKey) {
    try {
      const rawPrivateKey = await subtle.exportKey('pkcs8', privateKey);
      const derBase64 = Buffer.from(rawPrivateKey).toString('base64');
      const pem = `-----BEGIN EC PRIVATE KEY-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END EC PRIVATE KEY-----\n`;
      this.privateKeyPEM = pem;
      return pem;
    } catch (error) {
      throw new Error(`导出私钥时出错: ${error.message}`);
    }
  }

  /**
   * 导出公钥为 PEM 格式
   */
  async exportPublicKeyToPEM(publicKey) {
    try {
      const rawPublicKey = await subtle.exportKey('spki', publicKey);
      const derBase64 = Buffer.from(rawPublicKey).toString('base64');
      const pem = `-----BEGIN PUBLIC KEY-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
      this.publicKeyPEM = pem;
      return pem;
    } catch (error) {
      throw new Error(`导出公钥时出错: ${error.message}`);
    }
  }


  /**
   * 生成工厂配置证书链
   */
  async generateFactoryCertificateChain(serverNames = null) {
    try {
      console.log('开始生成工厂配置证书链...');
      
      // 1. 生成根 CA
      const rootCA = await this.generateRootCA({
        C: 'xyz',
        ST: 'wator',
        L: 'otmc',
        O: 'otmc',
        OU: 'dts',
        CN: 'Digital Twin Root CA for Factory Provisioning'
      }, 10);
      
      // 2. 配置 SAN
      const sanConfig = {
        critical: false,
        names: serverNames || [
          { type: 'dns', value: 'localhost' },
          { type: 'ip', value: '127.0.0.1' },
          { type: 'ip', value: '::1' },
          { type: 'dns', value: 'factory-provisioning.local' }
        ]
      };
      
      // 3. 生成服务器证书
      const serverCert = await this.generateServerCertificate(
        {
          C: 'xyz',
          ST: 'wator',
          L: 'otmc',
          O: 'otmc',
          OU: 'dts',
          CN: 'Digital Twin Server Certificate for Factory Provisioning'
        },
        20, // 20天有效期
        rootCA.keyPair,
        {
          C: 'xyz',
          ST: 'wator',
          L: 'otmc',
          O: 'otmc',
          OU: 'dts',
          CN: 'Digital Twin Root CA for Factory Provisioning'
        },
        null,
        sanConfig
      );
      
      console.log('✓ 工厂配置证书链生成完成');
      
      return {
        rootCA,
        serverCert
      };
      
    } catch (error) {
      throw new Error(`生成工厂配置证书链时出错: ${error.message}`);
    }
  }
}

export { ECDSACertificateGenerator };