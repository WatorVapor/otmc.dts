import { webcrypto } from 'crypto';
import { writeFile, readFile } from 'fs/promises';
import asn1 from 'asn1js';
import { Certificate } from 'pkijs';

const { subtle } = webcrypto;

/**
 * Ed25519 证书生成器类
 */
class Ed25519CertificateGenerator {
  constructor() {
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
          name: 'Ed25519',
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
              new asn1.ObjectIdentifier({ value: '1.3.101.112' })
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
              new asn1.ObjectIdentifier({ value: '1.3.101.112' })
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
      
      console.log('正在生成根 CA 证书...');
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
      console.log('正在生成Leaf证书...');
      
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
  async generateCSR(subject,validityYears = 10, subjectKeyPair = null) {
    try {
      if (!subjectKeyPair) {
        subjectKeyPair = await this.generateKeyPair();
      }

      console.log('正在生成CSR...');

      const notBefore = new Date();
      const notAfter = new Date();
      notAfter.setFullYear(notAfter.getFullYear() + validityYears);

      // 获取公钥的 DER 编码
      const rawPublicKey = await subtle.exportKey('spki', subjectKeyPair.publicKey);
      const publicKeyBuffer = new Uint8Array(rawPublicKey);
      const spkiASN1 = asn1.fromBER(publicKeyBuffer.buffer);
      if (spkiASN1.offset === -1) {
        throw new Error('Failed to parse SPKI');
      }

      // 构建 CSR 信息结构
      const certificationRequestInfo = new asn1.Sequence({
        value: [
          // 版本号
          new asn1.Integer({ value: 0 }),
          
          // 主题
          this.createName(subject),
          
          // 主题公钥信息
          spkiASN1.result,
          
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
      const signature = await subtle.sign(
        'Ed25519',
        subjectKeyPair.privateKey,
        csrInfoBuffer
      );

      // 构建完整的 CSR
      const csr = new asn1.Sequence({
        value: [
          certificationRequestInfo,
          
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
          { name: 'Ed25519' },
          true,
          ['verify']
        );
      }
      
      // 验证签名
      const isValid = await subtle.verify(
        'Ed25519',
        publicKey,
        signature,
        tbsBuffer
      );
      
      return isValid;
      
    } catch (error) {
      throw new Error(`验证CSR签名时出错: ${error.message}`);
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
}

// 导出类
export { Ed25519CertificateGenerator };
