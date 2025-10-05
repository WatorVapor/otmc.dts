import { webcrypto } from 'crypto';
import { writeFile, readFile } from 'fs/promises';
import asn1 from 'asn1js';

const { subtle } = webcrypto;

/**
 * Ed25519 证书生成器类
 */
class Ed25519CertificateGenerator {
  constructor() {
    this.keyUsages = {
      digitalSignature: 0x80, // 位0
      nonRepudiation: 0x40,   // 位1
      keyEncipherment: 0x20,  // 位2
      dataEncipherment: 0x10, // 位3
      keyAgreement: 0x08,     // 位4
      keyCertSign: 0x04,      // 位5
      cRLSign: 0x02,          // 位6
      encipherOnly: 0x01,     // 位7
      decipherOnly: 0x80      // 位7 (与encipherOnly相同位，但用于keyAgreement)
    };
    this.keyPair = null;
    this.privateKey = null;
    this.publicKey = null;
    this.privateKeyPEM = null;
    this.publicKeyPEM = null;

}

  /**
   * 生成随机的序列号
   */
  generateSerialNumber() {
    return webcrypto.getRandomValues(new Uint8Array(20));
  }

  /**
   * 将日期转换为 ASN.1 时间格式
   */
  dateToASN1(date) {
    const year = date.getUTCFullYear();
    
    if (year >= 1950 && year <= 2049) {
      const yy = year.toString().slice(-2).padStart(2, '0');
      const mm = (date.getUTCMonth() + 1).toString().padStart(2, '0');
      const dd = date.getUTCDate().toString().padStart(2, '0');
      const hh = date.getUTCHours().toString().padStart(2, '0');
      const min = date.getUTCMinutes().toString().padStart(2, '0');
      const ss = date.getUTCSeconds().toString().padStart(2, '0');
      return `${yy}${mm}${dd}${hh}${min}${ss}Z`;
    } else {
      const yyyy = year.toString().padStart(4, '0');
      const mm = (date.getUTCMonth() + 1).toString().padStart(2, '0');
      const dd = date.getUTCDate().toString().padStart(2, '0');
      const hh = date.getUTCHours().toString().padStart(2, '0');
      const min = date.getUTCMinutes().toString().padStart(2, '0');
      const ss = date.getUTCSeconds().toString().padStart(2, '0');
      return `${yyyy}${mm}${dd}${hh}${min}${ss}Z`;
    }
  }

  /**
   * 生成 Ed25519 密钥对
   */
  async generateKeyPair() {
    try {
      const keyPair = await subtle.generateKey(
        {
          name: 'Ed25519',
        },
        true,
        ['sign', 'verify']
      );
      this.keyPair = keyPair;
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
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
      const derBase64 = pem
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\n/g, '');
      
      const derBuffer = Buffer.from(derBase64, 'base64');
      
      const privateKey = await subtle.importKey(
        'pkcs8',
        derBuffer,
        {
          name: 'Ed25519',
        },
        true,
        ['sign']
      );
      this.privateKey = privateKey;
      this.privateKeyPEM = pem;
      if(!this.keyPair) {
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
      const derBase64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\n/g, '');
      
      const derBuffer = Buffer.from(derBase64, 'base64');
      
      const publicKey = await subtle.importKey(
        'spki',
        derBuffer,
        {
          name: 'Ed25519',
        },
        true,
        ['verify']
      );
      this.publicKey = publicKey;
      this.publicKeyPEM = pem;
      if(!this.keyPair) {
        this.keyPair = {};
      }
      this.keyPair.publicKey = publicKey;
      return publicKey;
    } catch (error) {
      throw new Error(`导入公钥时出错: ${error.message}`);
    }
  }

  /**
   * 导出私钥为 PEM 格式
   */
  async exportPrivateKeyToPEM(privateKey) {
    try {
      const rawPrivateKey = await subtle.exportKey('pkcs8', privateKey);
      const derBase64 = Buffer.from(rawPrivateKey).toString('base64');
      const pem = `-----BEGIN PRIVATE KEY-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
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
   * 从私钥创建公钥
   */
  async createPublicKeyFromPrivateKey() {
  }

  /**
   * 创建 X.509 名称结构
   */
  createName(nameComponents) {
    const nameAttributes = [];
    
    for (const [type, value] of Object.entries(nameComponents)) {
      let oid;
      switch (type.toUpperCase()) {
        case 'C': oid = '2.5.4.6'; break;
        case 'ST': oid = '2.5.4.8'; break;
        case 'L': oid = '2.5.4.7'; break;
        case 'O': oid = '2.5.4.10'; break;
        case 'OU': oid = '2.5.4.11'; break;
        case 'CN': oid = '2.5.4.3'; break;
        case 'EMAIL': oid = '1.2.840.113549.1.9.1'; break;
        default: continue;
      }
      
      nameAttributes.push(
        new asn1.Sequence({
          value: [
            new asn1.ObjectIdentifier({ value: oid }),
            new asn1.Utf8String({ value: value })
          ]
        })
      );
    }
    
    return new asn1.Sequence({
      value: [
        new asn1.Set({
          value: nameAttributes
        })
      ]
    });
  }

  /**
   * 创建证书扩展
   */
  createExtensions(extensionsConfig) {
    const extensions = [];
    
    // 基本约束
    if (extensionsConfig.basicConstraints) {
      extensions.push(
        new asn1.Sequence({
          value: [
            new asn1.ObjectIdentifier({ value: '2.5.29.19' }), // basicConstraints
            new asn1.Boolean({ value: extensionsConfig.basicConstraints.critical || true }),
            new asn1.OctetString({
              valueHex: new asn1.Sequence({
                value: [
                  new asn1.Boolean({ value: extensionsConfig.basicConstraints.isCA || false }),
                  ...(extensionsConfig.basicConstraints.pathLenConstraint !== undefined ? 
                    [new asn1.Integer({ value: extensionsConfig.basicConstraints.pathLenConstraint })] : [])
                ]
              }).toBER()
            })
          ]
        })
      );
    }
    
    // 密钥用法
    if (extensionsConfig.keyUsage) {
      const keyUsageBits = extensionsConfig.keyUsage.usage.reduce((bits, usage) => {
        return bits | (this.keyUsages[usage] || 0);
      }, 0);
      
      extensions.push(
        new asn1.Sequence({
          value: [
            new asn1.ObjectIdentifier({ value: '2.5.29.15' }), // keyUsage
            new asn1.Boolean({ value: extensionsConfig.keyUsage.critical || true }),
            new asn1.OctetString({
              valueHex: new asn1.BitString({
                valueHex: new Uint8Array([(keyUsageBits >> 8) & 0xFF, keyUsageBits & 0xFF])
              }).toBER()
            })
          ]
        })
      );
    }
    
    // 主题备用名称
    if (extensionsConfig.subjectAltName) {
      const altNames = extensionsConfig.subjectAltName.names.map(name => {
        if (name.type === 'dns') {
          return new asn1.Constructed({
            idBlock: {
              tagClass: 2, // context-specific
              tagNumber: 2 // dNSName
            },
            value: [new asn1.Utf8String({ value: name.value })]
          });
        } else if (name.type === 'ip') {
          return new asn1.Constructed({
            idBlock: {
              tagClass: 2, // context-specific
              tagNumber: 7 // iPAddress
            },
            value: [new asn1.OctetString({ valueHex: this.ipToBuffer(name.value) })]
          });
        }
      });
      
      extensions.push(
        new asn1.Sequence({
          value: [
            new asn1.ObjectIdentifier({ value: '2.5.29.17' }), // subjectAltName
            new asn1.Boolean({ value: extensionsConfig.subjectAltName.critical || false }),
            new asn1.OctetString({
              valueHex: new asn1.Sequence({
                value: altNames
              }).toBER()
            })
          ]
        })
      );
    }
    
    return new asn1.Sequence({ value: extensions });
  }

  /**
   * IP 地址转换为缓冲区
   */
  ipToBuffer(ip) {
    if (ip.includes(':')) {
      // IPv6
      const parts = ip.split(':');
      const buffer = new Uint8Array(16);
      let index = 0;
      
      for (const part of parts) {
        if (part === '') {
          // 处理 ::
          const zeros = 16 - (parts.length - 1) * 2;
          for (let i = 0; i < zeros; i++) {
            buffer[index++] = 0;
          }
        } else {
          const value = parseInt(part, 16);
          buffer[index++] = (value >> 8) & 0xFF;
          buffer[index++] = value & 0xFF;
        }
      }
      
      return buffer;
    } else {
      // IPv4
      const parts = ip.split('.');
      return new Uint8Array(parts.map(part => parseInt(part, 10)));
    }
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
      
      const notBefore = new Date();
      const notAfter = new Date();
      notAfter.setDate(notAfter.getDate() + validityDays);

      // 获取公钥的 DER 编码
      const rawPublicKey = await subtle.exportKey('spki', subjectKeyPair.publicKey);
      const publicKeyBuffer = new Uint8Array(rawPublicKey);
      const spkiASN1 = asn1.fromBER(publicKeyBuffer.buffer);
      if (spkiASN1.offset === -1) {
        throw new Error('Failed to parse SPKI');
      }

      // 构建 TBS 证书结构
      const tbsCertificate = new asn1.Sequence({
        value: [
          // 版本号 (v3)
          new asn1.Constructed({
            idBlock: {
              tagClass: 3, // context-specific
              tagNumber: 0
            },
            value: [
              new asn1.Integer({ value: 2 }) // v3
            ]
          }),
          
          // 序列号
          new asn1.Integer({ valueHex: Buffer.from(serialNumber) }),
          
          // 签名算法 (Ed25519)
          new asn1.Sequence({
            value: [
              new asn1.ObjectIdentifier({ value: '1.3.101.112' }) // Ed25519 OID
            ]
          }),
          
          // 颁发者
          this.createName(issuer),
          
          // 有效期
          new asn1.Sequence({
            value: [
              new asn1.UTCTime({ value: this.dateToASN1(notBefore) }),
              new asn1.UTCTime({ value: this.dateToASN1(notAfter) })
            ]
          }),
          
          // 主题
          this.createName(subject),
          
          // 主题公钥信息
          spkiASN1.result,
          
          // 扩展
          new asn1.Constructed({
            idBlock: {
              tagClass: 3,
              tagNumber: 3
            },
            value: [this.createExtensions(extensions)]
          })
        ]
      });

      // 对 TBS 证书进行签名
      const tbsBuffer = tbsCertificate.toBER();
      const signature = await subtle.sign(
        'Ed25519',
        issuerKeyPair.privateKey,
        tbsBuffer
      );

      // 构建完整的证书
      const certificate = new asn1.Sequence({
        value: [
          tbsCertificate,
          
          // 签名算法
          new asn1.Sequence({
            value: [
              new asn1.ObjectIdentifier({ value: '1.3.101.112' }) // Ed25519 OID
            ]
          }),
          
          // 签名值
          new asn1.BitString({
            valueHex: Buffer.from(signature)
          })
        ]
      });

      // 转换为 PEM 格式
      const derBuffer = certificate.toBER();
      const derBase64 = Buffer.from(derBuffer).toString('base64');
      const pem = `-----BEGIN CERTIFICATE-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

      return pem;

    } catch (error) {
      throw new Error(`生成证书时出错: ${error.message}`);
    }
  }

  /**
   * 生成根 CA 证书
   */
  async generateRootCA(subject, validityYears = 10) {
    try {
      
      console.log('正在生成根 CA 证书...');
      const certificate = await this.generateCertificate({
        subjectKeyPair: this.keyPair,
        issuerKeyPair: this.keyPair, // 自签名
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
            usage: ['keyCertSign', 'cRLSign']
          }
        }
      });

      console.log('✓ 根 CA 生成成功');
      return {
        keyPair: this.keyPair,
        certificate,
        privateKeyPEM: await this.exportPrivateKeyToPEM(this.keyPair.privateKey),
        publicKeyPEM: await this.exportPublicKeyToPEM(this.keyPair.publicKey)
      };

    } catch (error) {
      throw new Error(`生成根 CA 时出错: ${error.message}`);
    }
  }

  /**
   * 生成中间 CA 证书
   */
  async generateIntermediateCA(rootCA, subject, validityYears = 5) {
    try {
      console.log('正在生成中间 CA 密钥对...');
      const keyPair = await this.generateKeyPair();
      
      console.log('正在生成中间 CA 证书...');
      const certificate = await this.generateCertificate({
        subjectKeyPair: keyPair,
        issuerKeyPair: rootCA.keyPair,
        subject: subject,
        issuer: rootCA.subject,
        validityDays: validityYears * 365,
        extensions: {
          basicConstraints: {
            critical: true,
            isCA: true,
            pathLenConstraint: 0
          },
          keyUsage: {
            critical: true,
            usage: ['keyCertSign', 'cRLSign']
          }
        }
      });

      console.log('✓ 中间 CA 生成成功');
      return {
        keyPair,
        certificate,
        privateKeyPEM: await this.exportPrivateKeyToPEM(keyPair.privateKey),
        publicKeyPEM: await this.exportPublicKeyToPEM(keyPair.publicKey)
      };

    } catch (error) {
      throw new Error(`生成中间 CA 时出错: ${error.message}`);
    }
  }

  /**
   * 生成服务器证书
   */
  async generateServerCertificate(issuerCA, subject, domains = [], validityDays = 365) {
    try {
      console.log('正在生成服务器密钥对...');
      const keyPair = await this.generateKeyPair();
      
      const altNames = domains.map(domain => ({ type: 'dns', value: domain }));
      
      console.log('正在生成服务器证书...');
      const certificate = await this.generateCertificate({
        subjectKeyPair: keyPair,
        issuerKeyPair: issuerCA.keyPair,
        subject: subject,
        issuer: issuerCA.subject,
        validityDays: validityDays,
        extensions: {
          basicConstraints: {
            critical: true,
            isCA: false
          },
          keyUsage: {
            critical: true,
            usage: ['digitalSignature', 'keyEncipherment']
          },
          subjectAltName: {
            critical: false,
            names: altNames
          }
        }
      });

      console.log('✓ 服务器证书生成成功');
      return {
        keyPair,
        certificate,
        privateKeyPEM: await this.exportPrivateKeyToPEM(keyPair.privateKey),
        publicKeyPEM: await this.exportPublicKeyToPEM(keyPair.publicKey)
      };

    } catch (error) {
      throw new Error(`生成服务器证书时出错: ${error.message}`);
    }
  }

  /**
   * 验证密钥对
   */
  async verifyKeyPair(keyPair) {
    try {
      const testData = new TextEncoder().encode('测试数据');
      const signature = await subtle.sign('Ed25519', keyPair.privateKey, testData);
      const isValid = await subtle.verify('Ed25519', keyPair.publicKey, signature, testData);
      return isValid;
    } catch (error) {
      console.error('验证密钥对时出错:', error);
      return false;
    }
  }

  /**
   * 保存证书和密钥到文件
   */
  async saveToFiles(certData, baseName) {
    try {
      if (certData.privateKeyPEM) {
        await writeFile(`${baseName}_private.pem`, certData.privateKeyPEM);
      }
      if (certData.publicKeyPEM) {
        await writeFile(`${baseName}_public.pem`, certData.publicKeyPEM);
      }
      if (certData.certificate) {
        await writeFile(`${baseName}_certificate.pem`, certData.certificate);
      }
      console.log(`✓ 文件已保存: ${baseName}_*.pem`);
    } catch (error) {
      throw new Error(`保存文件时出错: ${error.message}`);
    }
  }
}

// 导出类
export { Ed25519CertificateGenerator };

/**
 * 使用示例
 */
async function exampleUsage() {
  const generator = new Ed25519CertificateGenerator();

  try {
    // 1. 生成根 CA
    const rootCA = await generator.generateRootCA({
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'My Company',
      OU: 'IT Department',
      CN: 'My Root CA'
    }, 10);

    await generator.saveToFiles(rootCA, 'root_ca');

    // 2. 生成中间 CA
    const intermediateCA = await generator.generateIntermediateCA(
      {
        keyPair: rootCA.keyPair,
        subject: rootCA.subject
      },
      {
        C: 'CN',
        ST: 'Beijing',
        L: 'Beijing',
        O: 'My Company',
        OU: 'Web Department',
        CN: 'My Intermediate CA'
      },
      5
    );

    await generator.saveToFiles(intermediateCA, 'intermediate_ca');

    // 3. 生成服务器证书
    const serverCert = await generator.generateServerCertificate(
      {
        keyPair: intermediateCA.keyPair,
        subject: intermediateCA.subject
      },
      {
        C: 'CN',
        ST: 'Beijing',
        L: 'Beijing',
        O: 'My Company',
        CN: 'api.example.com'
      },
      ['api.example.com', 'www.example.com'],
      365
    );

    await generator.saveToFiles(serverCert, 'server');

    console.log('=== 所有证书生成完成 ===');

  } catch (error) {
    console.error('示例执行出错:', error);
  }
}

// 运行示例
// exampleUsage();