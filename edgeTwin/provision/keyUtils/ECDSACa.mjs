import { webcrypto } from 'crypto';
import { writeFile, readFile } from 'fs/promises';
import asn1 from 'asn1js';
import { Certificate } from 'pkijs';

const { subtle } = webcrypto;

/**
 * ECDSA 证书生成器类 (使用 P-256 曲线)
 */
class ECDSACertificateGenerator {
  constructor() {
    // ECDSA 曲线配置
    this.curveNames = {
      'P-256': '1.2.840.10045.3.1.7', // prime256v1
      'P-384': '1.3.132.0.34',        // secp384r1
      'P-521': '1.3.132.0.35'         // secp521r1
    };
    
    this.algorithmOIDs = {
      'P-256': '1.2.840.10045.4.3.2', // ecdsaWithSHA256
      'P-384': '1.2.840.10045.4.3.3', // ecdsaWithSHA384
      'P-521': '1.2.840.10045.4.3.4'  // ecdsaWithSHA512
    };
    
    this.hashAlgorithms = {
      'P-256': 'SHA-256',
      'P-384': 'SHA-384',
      'P-521': 'SHA-512'
    };
    
    this.keyUsages = {
      digitalSignature: 0x80,
      nonRepudiation: 0x40,
      keyEncipherment: 0x20,
      dataEncipherment: 0x10,
      keyAgreement: 0x08,
      keyCertSign: 0x04,
      cRLSign: 0x02,
      encipherOnly: 0x01,
      decipherOnly: 0x80
    };
    
    this.extendedKeyUsages = {
      serverAuth: '1.3.6.1.5.5.7.3.1',
      clientAuth: '1.3.6.1.5.5.7.3.2',
      codeSigning: '1.3.6.1.5.5.7.3.3',
      emailProtection: '1.3.6.1.5.5.7.3.4',
      timeStamping: '1.3.6.1.5.5.7.3.8',
      ocspSigning: '1.3.6.1.5.5.7.3.9'
    };
    
    this.keyPair = null;
    this.privateKey = null;
    this.publicKey = null;
    this.privateKeyPEM = null;
    this.publicKeyPEM = null;
    this.curveName = 'P-384'; // 默认曲线
  }

  /**
   * 设置曲线
   */
  setCurve(curveName) {
    if (!this.curveNames[curveName]) {
      throw new Error(`不支持的曲线: ${curveName}. 支持: ${Object.keys(this.curveNames).join(', ')}`);
    }
    this.curveName = curveName;
    return this;
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
      const derBase64 = pem
        .replace(/-----BEGIN EC PRIVATE KEY-----/, '')
        .replace(/-----END EC PRIVATE KEY-----/, '')
        .replace(/\n/g, '');
      
      const derBuffer = Buffer.from(derBase64, 'base64');
      
      const privateKey = await subtle.importKey(
        'pkcs8',
        derBuffer,
        {
          name: 'ECDSA',
          namedCurve: this.curveName,
        },
        true,
        ['sign']
      );
      
      this.privateKey = privateKey;
      this.privateKeyPEM = pem;
      
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
      const derBase64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\n/g, '');
      
      const derBuffer = Buffer.from(derBase64, 'base64');
      
      const publicKey = await subtle.importKey(
        'spki',
        derBuffer,
        {
          name: 'ECDSA',
          namedCurve: this.curveName,
        },
        true,
        ['verify']
      );
      
      this.publicKey = publicKey;
      this.publicKeyPEM = pem;
      
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
   * 创建 ECDSA 公钥参数（曲线标识）
   */
  createECParameters() {
    return new asn1.Sequence({
      value: [
        new asn1.ObjectIdentifier({ value: '1.2.840.10045.2.1' }), // ecPublicKey
        new asn1.ObjectIdentifier({ value: this.curveNames[this.curveName] }) // 曲线 OID
      ]
    });
  }

  /**
   * 创建 ECDSA 主题公钥信息
   */
  createSubjectPublicKeyInfo(publicKeyBuffer) {
    return new asn1.Sequence({
      value: [
        // 算法标识
        this.createECParameters(),
        // 公钥位字符串
        new asn1.BitString({ valueHex: publicKeyBuffer })
      ]
    });
  }

  /**
   * 创建扩展密钥用法扩展
   */
  createExtendedKeyUsage(extendedKeyUsageConfig) {
    const keyPurposes = extendedKeyUsageConfig.usage.map(usage => {
      const oid = this.extendedKeyUsages[usage];
      if (!oid) {
        throw new Error(`不支持的扩展密钥用法: ${usage}`);
      }
      return new asn1.ObjectIdentifier({ value: oid });
    });

    return new asn1.Sequence({
      value: [
        new asn1.ObjectIdentifier({ value: '2.5.29.37' }), // extendedKeyUsage
        new asn1.Boolean({ value: extendedKeyUsageConfig.critical || false }),
        new asn1.OctetString({
          valueHex: new asn1.Sequence({
            value: keyPurposes
          }).toBER()
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
            new asn1.ObjectIdentifier({ value: '2.5.29.19' }),
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
            new asn1.ObjectIdentifier({ value: '2.5.29.15' }),
            new asn1.Boolean({ value: extensionsConfig.keyUsage.critical || true }),
            new asn1.OctetString({
              valueHex: new asn1.BitString({
                valueHex: new Uint8Array([keyUsageBits & 0xFF]),
                unusedBits: 0
              }).toBER()
            })
          ]
        })
      );
    }
    
    // 扩展密钥用法
    if (extensionsConfig.extendedKeyUsage) {
      extensions.push(this.createExtendedKeyUsage(extensionsConfig.extendedKeyUsage));
    }
    
    // 主题备用名称
    if (extensionsConfig.subjectAltName) {
      const altNames = extensionsConfig.subjectAltName.names.map(name => {
        if (name.type === 'dns') {
          return new asn1.Constructed({
            idBlock: {
              tagClass: 2,
              tagNumber: 2
            },
            value: [new asn1.Utf8String({ value: name.value })]
          });
        } else if (name.type === 'ip') {
          return new asn1.Constructed({
            idBlock: {
              tagClass: 2,
              tagNumber: 7
            },
            value: [new asn1.OctetString({ valueHex: this.ipToBuffer(name.value) })]
          });
        } else if (name.type === 'email') {
          return new asn1.Constructed({
            idBlock: {
              tagClass: 2,
              tagNumber: 1
            },
            value: [new asn1.IA5String({ value: name.value })]
          });
        }
      }).filter(Boolean);
      
      extensions.push(
        new asn1.Sequence({
          value: [
            new asn1.ObjectIdentifier({ value: '2.5.29.17' }),
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
   * 对数据进行签名
   */
  async signData(data, privateKey) {
    const hashAlgorithm = this.hashAlgorithms[this.curveName];
    
    const signature = await subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: hashAlgorithm }
      },
      privateKey,
      data
    );
    
    return new Uint8Array(signature);
  }

  /**
   * 验证签名
   */
  async verifySignature(data, signature, publicKey) {
    const hashAlgorithm = this.hashAlgorithms[this.curveName];
    
    const isValid = await subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: hashAlgorithm }
      },
      publicKey,
      signature,
      data
    );
    
    return isValid;
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
      
      // 构建 TBS 证书结构
      const tbsCertificate = new asn1.Sequence({
        value: [
          // 版本号 (v3)
          new asn1.Constructed({
            idBlock: {
              tagClass: 3,
              tagNumber: 0
            },
            value: [
              new asn1.Integer({ value: 2 })
            ]
          }),
          
          // 序列号
          new asn1.Integer({ valueHex: Buffer.from(serialNumber) }),
          
          // 签名算法
          new asn1.Sequence({
            value: [
              new asn1.ObjectIdentifier({ value: this.algorithmOIDs[this.curveName] })
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
          this.createSubjectPublicKeyInfo(publicKeyBuffer),
          
          // 扩展
          ...(Object.keys(extensions).length > 0 ? [
            new asn1.Constructed({
              idBlock: {
                tagClass: 3,
                tagNumber: 3
              },
              value: [this.createExtensions(extensions)]
            })
          ] : [])
        ]
      });

      // 对 TBS 证书进行签名
      const tbsBuffer = tbsCertificate.toBER();
      const signature = await this.signData(tbsBuffer, issuerKeyPair.privateKey);

      // 构建完整的证书
      const certificate = new asn1.Sequence({
        value: [
          tbsCertificate,
          
          // 签名算法
          new asn1.Sequence({
            value: [
              new asn1.ObjectIdentifier({ value: this.algorithmOIDs[this.curveName] })
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
            usage: ['keyCertSign', 'cRLSign']
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
   * 生成Leaf证书
   */
  async generateLeafCertificate(subject, validityDays = 365, issuerKeyPair, issuerCertPem, subjectKeyPair = null) {
    try {
      if (!subjectKeyPair) {
        subjectKeyPair = await this.generateKeyPair();
      }
      
      const issuerSubject = this.loadSubjectFromCertPem(issuerCertPem);
      console.log(`正在生成 ${this.curveName} Leaf证书...`);
      
      const certificate = await this.generateCertificate({
        subjectKeyPair: subjectKeyPair,
        issuerKeyPair: issuerKeyPair,
        subject: subject,
        issuer: issuerSubject.fields,
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
          }
        }
      });
      
      console.log('✓ Leaf证书生成成功');
      return {
        certificate,
        keyPair: subjectKeyPair,
        privateKeyPEM: await this.exportPrivateKeyToPEM(subjectKeyPair.privateKey),
        publicKeyPEM: await this.exportPublicKeyToPEM(subjectKeyPair.publicKey)
      };

    } catch (error) {
      throw new Error(`生成Leaf证书时出错: ${error.message}`);
    }
  }

  /**
   * 生成CSR Certificate Signing Request
   */
  async generateCSR(subject, validityYears = 10, subjectKeyPair = null) {
    try {
      if (!subjectKeyPair) {
        subjectKeyPair = await this.generateKeyPair();
      }

      console.log(`正在生成 ${this.curveName} CSR...`);

      const notBefore = new Date();
      const notAfter = new Date();
      notAfter.setFullYear(notAfter.getFullYear() + validityYears);

      // 获取公钥的 DER 编码
      const rawPublicKey = await subtle.exportKey('spki', subjectKeyPair.publicKey);
      const publicKeyBuffer = new Uint8Array(rawPublicKey);

      // 构建 CSR 信息结构
      const certificationRequestInfo = new asn1.Sequence({
        value: [
          // 版本号
          new asn1.Integer({ value: 0 }),
          
          // 主题
          this.createName(subject),
          
          // 主题公钥信息
          this.createSubjectPublicKeyInfo(publicKeyBuffer),
          
          // 属性（可选，用于请求扩展）
          new asn1.Constructed({
            idBlock: {
              tagClass: 3,
              tagNumber: 0
            },
            value: [
              new asn1.Sequence({
                value: [
                  // 扩展请求属性
                  new asn1.Sequence({
                    value: [
                      new asn1.ObjectIdentifier({ value: '1.2.840.113549.1.9.14' }), // extensionRequest
                      new asn1.Set({
                        value: [
                          new asn1.Sequence({
                            value: [this.createExtensions({
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
                              }
                            })]
                          })
                        ]
                      })
                    ]
                  })
                ]
              })
            ]
          })
        ]
      });

      // 对 CSR 信息进行签名
      const csrInfoBuffer = certificationRequestInfo.toBER();
      const signature = await this.signData(csrInfoBuffer, subjectKeyPair.privateKey);

      // 构建完整的 CSR
      const csr = new asn1.Sequence({
        value: [
          certificationRequestInfo,
          
          // 签名算法
          new asn1.Sequence({
            value: [
              new asn1.ObjectIdentifier({ value: this.algorithmOIDs[this.curveName] })
            ]
          }),
          
          // 签名值
          new asn1.BitString({
            valueHex: Buffer.from(signature)
          })
        ]
      });

      // 转换为 PEM 格式
      const derBuffer = csr.toBER();
      const derBase64 = Buffer.from(derBuffer).toString('base64');
      const csrPEM = `-----BEGIN CERTIFICATE REQUEST-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE REQUEST-----\n`;

      console.log('✓ CSR生成成功');
      return {
        csr: csrPEM,
        keyPair: subjectKeyPair,
        privateKeyPEM: await this.exportPrivateKeyToPEM(subjectKeyPair.privateKey),
        publicKeyPEM: await this.exportPublicKeyToPEM(subjectKeyPair.publicKey)
      };

    } catch (error) {
      throw new Error(`生成CSR时出错: ${error.message}`);
    }
  }

  /**
   * 从CSR PEM解析主题信息
   */
  parseSubjectFromCSR(csrPEM) {
    try {
      // 清理PEM格式
      const pemClean = csrPEM
        .replace(/-----BEGIN CERTIFICATE REQUEST-----/, '')
        .replace(/-----END CERTIFICATE REQUEST-----/, '')
        .replace(/\n/g, '');
      
      // 将Base64转换为ArrayBuffer
      const csrDER = Uint8Array.from(Buffer.from(pemClean, 'base64'));
      const asn1Obj = asn1.fromBER(csrDER.buffer);
      
      if (asn1Obj.offset === -1) {
        throw new Error('ASN.1解析失败');
      }
      
      // 解析CSR结构
      const csrSequence = asn1Obj.result;
      const certificationRequestInfo = csrSequence.valueBlock.value[0]; // 第一个元素是CertificationRequestInfo
      
      // 主题是CertificationRequestInfo中的第二个元素（索引1）
      const subjectSequence = certificationRequestInfo.valueBlock.value[1];
      
      // 解析主题信息
      const subjectInfo = {
        raw: subjectSequence,
        fields: {},
        string: ''
      };
      
      // 主题是一个Sequence of Set of Sequence
      const subjectSet = subjectSequence.valueBlock.value[0]; // 第一个Set
      
      subjectSet.valueBlock.value.forEach(attrSeq => {
        const attrType = attrSeq.valueBlock.value[0]; // OID
        const attrValue = attrSeq.valueBlock.value[1]; // 值
        
        const oid = attrType.valueBlock.toString();
        const value = attrValue.valueBlock.toString();
        
        const fieldMap = {
          '2.5.4.3': 'CN',
          '2.5.4.6': 'C',
          '2.5.4.7': 'L',
          '2.5.4.8': 'ST',
          '2.5.4.10': 'O',
          '2.5.4.11': 'OU',
          '1.2.840.113549.1.9.1': 'EMAIL'
        };
        
        const fieldName = fieldMap[oid] || oid;
        subjectInfo.fields[fieldName] = value;
        
        // 构建主题字符串
        if (subjectInfo.string) {
          subjectInfo.string += ', ';
        }
        subjectInfo.string += `${fieldName}=${value}`;
      });
      
      return subjectInfo;
      
    } catch (error) {
      throw new Error(`从CSR解析主题信息时出错: ${error.message}`);
    }
  }

  /**
   * 验证CSR签名
   */
  async verifyCSR(csrPEM, publicKeyPEM = null) {
    try {
      // 清理PEM格式
      const pemClean = csrPEM
        .replace(/-----BEGIN CERTIFICATE REQUEST-----/, '')
        .replace(/-----END CERTIFICATE REQUEST-----/, '')
        .replace(/\n/g, '');
      
      const csrDER = Uint8Array.from(Buffer.from(pemClean, 'base64'));
      const asn1Obj = asn1.fromBER(csrDER.buffer);
      
      if (asn1Obj.offset === -1) {
        throw new Error('ASN.1解析失败');
      }
      
      const csrSequence = asn1Obj.result;
      const certificationRequestInfo = csrSequence.valueBlock.value[0];
      const signatureAlgorithm = csrSequence.valueBlock.value[1];
      const signatureValue = csrSequence.valueBlock.value[2];
      
      // 获取签名数据
      const tbsBuffer = certificationRequestInfo.toBER();
      const signature = signatureValue.valueBlock.valueHex;
      
      let publicKey;
      
      if (publicKeyPEM) {
        // 使用提供的公钥验证
        publicKey = await this.importPublicKeyFromPEM(publicKeyPEM);
      } else {
        // 从CSR中提取公钥
        const subjectPKInfo = certificationRequestInfo.valueBlock.value[2]; // 第三个元素是公钥信息
        const publicKeyBuffer = subjectPKInfo.toBER();
        publicKey = await subtle.importKey(
          'spki',
          publicKeyBuffer,
          { 
            name: 'ECDSA',
            namedCurve: this.curveName
          },
          true,
          ['verify']
        );
      }
      
      // 验证签名
      const isValid = await this.verifySignature(tbsBuffer, signature, publicKey);
      
      return isValid;
      
    } catch (error) {
      throw new Error(`验证CSR签名时出错: ${error.message}`);
    }
  }

  /**
   * 从 CSR 签发证书
   */
  async signCSR(csrPEM, issuerKeyPair, issuerSubject, validityDays = 365, extensions = {}) {
    try {
      // 从 CSR 解析主题和公钥
      const subjectInfo = this.parseSubjectFromCSR(csrPEM);
      
      // 从 CSR 提取公钥
      const pemClean = csrPEM
        .replace(/-----BEGIN CERTIFICATE REQUEST-----/, '')
        .replace(/-----END CERTIFICATE REQUEST-----/, '')
        .replace(/\n/g, '');
      
      const csrDER = Uint8Array.from(Buffer.from(pemClean, 'base64'));
      const asn1Obj = asn1.fromBER(csrDER.buffer);
      
      if (asn1Obj.offset === -1) {
        throw new Error('ASN.1 解析失败');
      }
      
      const csrSequence = asn1Obj.result;
      const certificationRequestInfo = csrSequence.valueBlock.value[0];
      const subjectPKInfo = certificationRequestInfo.valueBlock.value[2]; // 公钥信息
      
      // 导入公钥
      const publicKeyBuffer = subjectPKInfo.toBER();
      const publicKey = await subtle.importKey(
        'spki',
        publicKeyBuffer,
        { 
          name: 'ECDSA',
          namedCurve: this.curveName
        },
        true,
        ['verify']
      );
      
      // 创建临时密钥对对象用于证书生成
      const subjectKeyPair = {
        publicKey: publicKey,
        privateKey: null // CSR 不包含私钥
      };
      
      console.log('正在从 CSR 签发证书...');
      const certificate = await this.generateCertificate({
        subjectKeyPair: subjectKeyPair,
        issuerKeyPair: issuerKeyPair,
        subject: subjectInfo.fields,
        issuer: issuerSubject,
        validityDays: validityDays,
        extensions: extensions
      });
      
      console.log('✓ 从 CSR 签发证书成功');
      return certificate;
      
    } catch (error) {
      throw new Error(`从 CSR 签发证书时出错: ${error.message}`);
    }
  }

  /**
   * 使用PKIJS从证书中加载主题信息
   */
  loadSubjectFromCertPem(certPEM) {
    try {
      // 清理PEM格式
      const pemClean = certPEM
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\n/g, '');
      
      // 将Base64转换为ArrayBuffer
      const certDER = Uint8Array.from(Buffer.from(pemClean, 'base64'));
      const asn1Obj = asn1.fromBER(certDER.buffer);
      
      if (asn1Obj.offset === -1) {
        throw new Error('ASN.1解析失败');
      }
      
      // 使用PKIJS解析证书
      const certificate = new Certificate({ schema: asn1Obj.result });
      
      // 提取主题信息
      const subject = certificate.subject;
      
      // 将主题信息转换为更易用的格式
      const subjectInfo = {
        raw: subject,
        fields: {},
        string: subject.toString()
      };
      
      // 解析各个字段
      subject.typesAndValues.forEach(field => {
        const type = field.type;
        const value = field.value.valueBlock.value;
        
        const fieldMap = {
          '2.5.4.3': 'CN',
          '2.5.4.6': 'C',
          '2.5.4.7': 'L',
          '2.5.4.8': 'ST',
          '2.5.4.10': 'O',
          '2.5.4.11': 'OU',
          '1.2.840.113549.1.9.1': 'EMAIL'
        };
        
        const fieldName = fieldMap[type] || type;
        subjectInfo.fields[fieldName] = value;
      });
      
      return subjectInfo;
      
    } catch (error) {
      throw new Error(`从证书中加载主题信息时出错: ${error.message}`);
    }
  }

  /**
   * 验证密钥对
   */
  async verifyKeyPair(keyPair) {
    try {
      const testData = new TextEncoder().encode('测试数据');
      const hashAlgorithm = this.hashAlgorithms[this.curveName];
      
      const signature = await subtle.sign(
        {
          name: 'ECDSA',
          hash: { name: hashAlgorithm }
        },
        keyPair.privateKey,
        testData
      );
      
      const isValid = await subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: hashAlgorithm }
        },
        keyPair.publicKey,
        signature,
        testData
      );
      
      return isValid;
    } catch (error) {
      console.error('验证密钥对时出错:', error);
      return false;
    }
  }

  /**
   * 验证证书签名
   */
  async verifyCertificate(certPEM, publicKeyPEM) {
    try {
      // 加载证书
      const pemClean = certPEM
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\n/g, '');
      
      const certDER = Uint8Array.from(Buffer.from(pemClean, 'base64'));
      const asn1Obj = asn1.fromBER(certDER.buffer);
      
      if (asn1Obj.offset === -1) {
        throw new Error('ASN.1解析失败');
      }
      
      const certificate = new Certificate({ schema: asn1Obj.result });
      
      // 提取TBS证书和签名
      const tbsCertificate = certificate.tbsView;
      const signature = certificate.signatureValue;
      
      // 导入验证公钥
      const publicKey = await this.importPublicKeyFromPEM(publicKeyPEM);
      
      // 验证签名
      const isValid = await this.verifySignature(tbsCertificate, signature, publicKey);
      
      return isValid;
      
    } catch (error) {
      throw new Error(`验证证书签名时出错: ${error.message}`);
    }
  }

  /**
   * 保存证书和密钥到文件
   */
  async saveToFiles(certData, baseName) {
    try {
      if (certData.privateKeyPEM) {
        await writeFile(`${baseName}_private.pem`, certData.privateKeyPEM);
        console.log(`✓ 私钥已保存: ${baseName}_private.pem`);
      }
      if (certData.publicKeyPEM) {
        await writeFile(`${baseName}_public.pem`, certData.publicKeyPEM);
        console.log(`✓ 公钥已保存: ${baseName}_public.pem`);
      }
      if (certData.certificate) {
        await writeFile(`${baseName}_certificate.pem`, certData.certificate);
        console.log(`✓ 证书已保存: ${baseName}_certificate.pem`);
      }
      if (certData.csr) {
        await writeFile(`${baseName}_csr.pem`, certData.csr);
        console.log(`✓ CSR已保存: ${baseName}_csr.pem`);
      }
    } catch (error) {
      throw new Error(`保存文件时出错: ${error.message}`);
    }
  }

  /**
   * 从文件加载证书
   */
  async loadCertificateFromFile(filename) {
    try {
      const pem = await readFile(filename, 'utf8');
      return pem;
    } catch (error) {
      throw new Error(`从文件加载证书时出错: ${error.message}`);
    }
  }

  /**
   * 清理敏感数据
   */
  clearSensitiveData() {
    this.privateKey = null;
    this.privateKeyPEM = null;
    this.keyPair = null;
    
    // 强制垃圾回收（如果可用）
    if (global.gc) {
      global.gc();
    }
  }
}

// 使用示例
async function example() {
  const generator = new ECDSACertificateGenerator();
  
  try {
    // 使用 P-256 曲线
    generator.setCurve('P-256');
    
    // 1. 生成根 CA
    const rootCA = await generator.generateRootCA({
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'Example Corp',
      OU: 'IT Department',
      CN: 'Example Root CA'
    });
    
    await generator.saveToFiles(rootCA, 'root-ca');
    
    // 2. 生成 CSR
    const csrData = await generator.generateCSR({
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'Example Corp',
      OU: 'Web Services',
      CN: 'api.example.com'
    });
    
    // 3. 验证 CSR
    const isValidCSR = await generator.verifyCSR(csrData.csr);
    console.log('CSR 签名验证:', isValidCSR);
    
    // 4. 从 CSR 签发证书
    const leafCert = await generator.signCSR(
      csrData.csr,
      rootCA.keyPair,
      {
        C: 'CN',
        ST: 'Beijing',
        L: 'Beijing',
        O: 'Example Corp',
        OU: 'IT Department',
        CN: 'Example Root CA'
      },
      365,
      {
        subjectAltName: {
          critical: false,
          names: [
            { type: 'dns', value: 'api.example.com' },
            { type: 'dns', value: 'www.example.com' }
          ]
        }
      }
    );
    
    await writeFile('leaf-certificate.pem', leafCert);
    
    // 5. 验证证书
    const isValidCert = await generator.verifyCertificate(
      leafCert,
      rootCA.publicKeyPEM
    );
    console.log('证书验证:', isValidCert);
    
  } catch (error) {
    console.error('错误:', error.message);
  } finally {
    generator.clearSensitiveData();
  }
}

// 导出类
export { ECDSACertificateGenerator };