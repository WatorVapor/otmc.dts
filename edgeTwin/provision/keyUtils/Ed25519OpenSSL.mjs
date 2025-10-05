import { execSync } from 'child_process';
import { writeFileSync, readFileSync } from 'fs';
import { webcrypto } from 'crypto';
import tmp from 'tmp';
/**
 * Ed25519 证书生成器类(OpenSSL)
 */
class Ed25519OpenSSL {
  constructor() {
    this.trace = true;
    this.debug = true;

    this.keyPair = null;
    this.privateKey = null;
    this.publicKey = null;
    this.privateKeyPEM = null;
    this.publicKeyPEM = null;
}

  /**
   * 生成 Ed25519 密钥对
   */
  async generateKeyPair() {
    // 创建临时目录保存 OpenSSL 生成的密钥
    const tmpDir = tmp.dirSync({ unsafeCleanup: true });
    const privateKeyPath = `${tmpDir.name}/ed25519_private.pem`;
    const publicKeyPath = `${tmpDir.name}/ed25519_public.pem`;

    try {
      // 使用 OpenSSL 生成 Ed25519 私钥
      execSync(`openssl genpkey -algorithm ed25519 -out ${privateKeyPath}`, { stdio: 'inherit' });
      // 从私钥导出公钥
      execSync(`openssl pkey -in ${privateKeyPath} -pubout -out ${publicKeyPath}`, { stdio: 'inherit' });
      // 读取 PEM 内容
      const privateKeyPEM = readFileSync(privateKeyPath, 'utf8');
      const publicKeyPEM = readFileSync(publicKeyPath, 'utf8');
      // 清理临时文件
      tmpDir.removeCallback();
      return {
        privateKey: privateKeyPEM,
        publicKey: publicKeyPEM,
      };
    } catch (error) {
      tmpDir.removeCallback();
      throw new Error(`OpenSSL 生成 Ed25519 密钥对失败: ${error.message}`);
    }
  }

  /**
   * 生成随机的序列号
   */
  generateSerialNumber() {
    return webcrypto.getRandomValues(new Uint8Array(20));
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
        subjectKey,
        issuerKey,
        subject,
        issuer,
        serialNumber = this.generateSerialNumber(),
        validityDays = 365,
        extensions = {}
      } = params;
      if(this.trace) {
        console.log('Ed25519OpenSSL::generateCertificate::params:=<', params, '>');
      }
      
      const notBefore = new Date();
      const notAfter = new Date();
      notAfter.setDate(notAfter.getDate() + validityDays);
      if(this.trace) {
        console.log('Ed25519OpenSSL::generateCertificate::notBefore:=<', notBefore, '>');
        console.log('Ed25519OpenSSL::generateCertificate::notAfter:=<', notAfter, '>');
      }

    } catch (error) {
      throw new Error(`生成证书时出错: ${error.message}`);
    }
  }

  /**
   * 生成根 CA 证书
   */
  async generateRootCA(subject, validityYears = 10,subjectKey,issuerKey) {
    try {
      
      console.log('正在生成根 CA 证书...');
      const certificate = await this.generateCertificate({
        subjectKey: subjectKey,
        issuerKey: issuerKey, // 自签名
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
        certificate,
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
export { Ed25519OpenSSL };

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