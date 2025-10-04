import { webcrypto } from 'crypto';
import { writeFile } from 'fs/promises';
import asn1 from 'asn1js';

const { subtle } = webcrypto;

/**
 * 生成随机的序列号 (20字节)
 */
function generateSerialNumber() {
  return webcrypto.getRandomValues(new Uint8Array(20));
}

/**
 * 将日期转换为 ASN.1 时间格式
 */
function dateToASN1(date) {
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
async function generateEd25519KeyPair() {
  try {
    const keyPair = await subtle.generateKey(
      {
        name: 'Ed25519',
      },
      true,
      ['sign', 'verify']
    );
    return keyPair;
  } catch (error) {
    console.error('生成密钥对时出错:', error);
    throw error;
  }
}

/**
 * 导出私钥为 PEM 格式
 */
async function exportPrivateKeyToPEM(privateKey) {
  try {
    const rawPrivateKey = await subtle.exportKey('pkcs8', privateKey);
    const derBase64 = Buffer.from(rawPrivateKey).toString('base64');
    const pem = `-----BEGIN PRIVATE KEY-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
    return pem;
  } catch (error) {
    console.error('导出私钥时出错:', error);
    throw error;
  }
}

/**
 * 导出公钥为 PEM 格式
 */
async function exportPublicKeyToPEM(publicKey) {
  try {
    const rawPublicKey = await subtle.exportKey('spki', publicKey);
    const derBase64 = Buffer.from(rawPublicKey).toString('base64');
    const pem = `-----BEGIN PUBLIC KEY-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
    return pem;
  } catch (error) {
    console.error('导出公钥时出错:', error);
    throw error;
  }
}

/**
 * 创建 X.509 名称结构
 */
function createName(nameComponents) {
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
 * 通用证书生成函数
 */
async function generateCertificate(tbsCertificate, signingKeyPair) {
  try {
    // 对 TBS 证书进行签名
    const tbsBuffer = tbsCertificate.toBER();
    const signature = await subtle.sign(
      'Ed25519',
      signingKeyPair.privateKey,
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
    
    // 转换为 DER 编码
    const derBuffer = certificate.toBER();
    const derBase64 = Buffer.from(derBuffer).toString('base64');
    
    // 格式化为 PEM
    const pem = `-----BEGIN CERTIFICATE-----\n${derBase64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
    
    return pem;
  } catch (error) {
    console.error('生成证书时出错:', error);
    throw error;
  }
}

/**
 * 创建根 CA 证书
 */
async function generateRootCACertificate(keyPair, subject) {
  try {
    console.log('正在生成根 CA 证书...');
    
    // 证书信息
    const serialNumber = generateSerialNumber();
    const notBefore = new Date();
    const notAfter = new Date();
    notAfter.setFullYear(notAfter.getFullYear() + 10);
    
    // 获取公钥的 DER 编码
    const rawPublicKey = await subtle.exportKey('spki', keyPair.publicKey);
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
            new asn1.ObjectIdentifier({ value: '1.3.101.112' })
          ]
        }),
        
        // 颁发者 (自签名)
        createName(subject),
        
        // 有效期
        new asn1.Sequence({
          value: [
            new asn1.UTCTime({ value: dateToASN1(notBefore) }),
            new asn1.UTCTime({ value: dateToASN1(notAfter) })
          ]
        }),
        
        // 主题
        createName(subject),
        
        // 主题公钥信息
        new asn1.fromBER(publicKeyBuffer.buffer).result,
        
        // 扩展
        new asn1.Constructed({
          idBlock: {
            tagClass: 3,
            tagNumber: 3
          },
          value: [
            new asn1.Sequence({
              value: [
                // 基本约束扩展
                new asn1.Sequence({
                  value: [
                    new asn1.ObjectIdentifier({ value: '2.5.29.19' }),
                    new asn1.Boolean({ value: true }),
                    new asn1.OctetString({
                      valueHex: new asn1.Sequence({
                        value: [
                          new asn1.Boolean({ value: true }) // CA: TRUE
                        ]
                      }).toBER()
                    })
                  ]
                }),
                
                // 密钥用法扩展
                new asn1.Sequence({
                  value: [
                    new asn1.ObjectIdentifier({ value: '2.5.29.15' }),
                    new asn1.Boolean({ value: true }),
                    new asn1.OctetString({
                      valueHex: new asn1.BitString({
                        valueHex: new Uint8Array([0x06, 0x05]) // keyCertSign + cRLSign
                      }).toBER()
                    })
                  ]
                })
              ]
            })
          ]
        })
      ]
    });
    
    const certificatePEM = await generateCertificate(tbsCertificate, keyPair);
    console.log('✓ 根 CA 证书生成成功');
    return certificatePEM;
    
  } catch (error) {
    console.error('生成根 CA 证书时出错:', error);
    throw error;
  }
}

/**
 * 生成中间 CA 证书
 */
async function generateIntermediateCACertificate(intermediateKeyPair, caKeyPair, caSubject, intermediateSubject) {
  try {
    console.log('正在生成中间 CA 证书...');
    
    // 证书信息
    const serialNumber = generateSerialNumber();
    const notBefore = new Date();
    const notAfter = new Date();
    notAfter.setFullYear(notAfter.getFullYear() + 5); // 中间 CA 有效期 5 年
    
    // 获取中间 CA 公钥的 DER 编码
    const rawPublicKey = await subtle.exportKey('spki', intermediateKeyPair.publicKey);
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
            new asn1.ObjectIdentifier({ value: '1.3.101.112' })
          ]
        }),
        
        // 颁发者 (根 CA)
        createName(caSubject),
        
        // 有效期
        new asn1.Sequence({
          value: [
            new asn1.UTCTime({ value: dateToASN1(notBefore) }),
            new asn1.UTCTime({ value: dateToASN1(notAfter) })
          ]
        }),
        
        // 主题 (中间 CA)
        createName(intermediateSubject),
        
        // 主题公钥信息
        new asn1.fromBER(publicKeyBuffer.buffer).result,
        
        // 扩展
        new asn1.Constructed({
          idBlock: {
            tagClass: 3,
            tagNumber: 3
          },
          value: [
            new asn1.Sequence({
              value: [
                // 基本约束扩展
                new asn1.Sequence({
                  value: [
                    new asn1.ObjectIdentifier({ value: '2.5.29.19' }),
                    new asn1.Boolean({ value: true }),
                    new asn1.OctetString({
                      valueHex: new asn1.Sequence({
                        value: [
                          new asn1.Boolean({ value: true }), // CA: TRUE
                          new asn1.Integer({ value: 0 }) // pathLenConstraint: 0 (不能再签发下级CA)
                        ]
                      }).toBER()
                    })
                  ]
                }),
                
                // 密钥用法扩展
                new asn1.Sequence({
                  value: [
                    new asn1.ObjectIdentifier({ value: '2.5.29.15' }),
                    new asn1.Boolean({ value: true }),
                    new asn1.OctetString({
                      valueHex: new asn1.BitString({
                        valueHex: new Uint8Array([0x06, 0x05]) // keyCertSign + cRLSign
                      }).toBER()
                    })
                  ]
                })
              ]
            })
          ]
        })
      ]
    });
    
    const certificatePEM = await generateCertificate(tbsCertificate, caKeyPair);
    console.log('✓ 中间 CA 证书生成成功');
    return certificatePEM;
    
  } catch (error) {
    console.error('生成中间 CA 证书时出错:', error);
    throw error;
  }
}

/**
 * 生成服务器证书
 */
async function generateServerCertificate(serverKeyPair, caKeyPair, caSubject, serverSubject, sanDnsNames = []) {
  try {
    console.log('正在生成服务器证书...');
    
    // 证书信息
    const serialNumber = generateSerialNumber();
    const notBefore = new Date();
    const notAfter = new Date();
    notAfter.setFullYear(notAfter.getFullYear() + 1); // 服务器证书有效期 1 年
    
    // 获取服务器公钥的 DER 编码
    const rawPublicKey = await subtle.exportKey('spki', serverKeyPair.publicKey);
    const publicKeyBuffer = new Uint8Array(rawPublicKey);
    
    // 构建扩展列表
    const extensions = [
      // 基本约束扩展
      new asn1.Sequence({
        value: [
          new asn1.ObjectIdentifier({ value: '2.5.29.19' }),
          new asn1.Boolean({ value: true }),
          new asn1.OctetString({
            valueHex: new asn1.Sequence({
              value: [
                new asn1.Boolean({ value: false }) // CA: FALSE
              ]
            }).toBER()
          })
        ]
      }),
      
      // 密钥用法扩展
      new asn1.Sequence({
        value: [
          new asn1.ObjectIdentifier({ value: '2.5.29.15' }),
          new asn1.Boolean({ value: true }),
          new asn1.OctetString({
            valueHex: new asn1.BitString({
              valueHex: new Uint8Array([0x80, 0x00]) // digitalSignature
            }).toBER()
          })
        ]
      }),
      
      // 扩展密钥用法
      new asn1.Sequence({
        value: [
          new asn1.ObjectIdentifier({ value: '2.5.29.37' }),
          new asn1.Boolean({ value: false }),
          new asn1.OctetString({
            valueHex: new asn1.Sequence({
              value: [
                new asn1.ObjectIdentifier({ value: '1.3.6.1.5.5.7.3.1' }), // serverAuth
                new asn1.ObjectIdentifier({ value: '1.3.6.1.5.5.7.3.2' })  // clientAuth
              ]
            }).toBER()
          })
        ]
      })
    ];
    
    // 如果提供了主题备用名称，添加 SAN 扩展
    if (sanDnsNames.length > 0) {
      const generalNames = sanDnsNames.map(dnsName => 
        new asn1.Constructed({
          idBlock: {
            tagClass: 3,
            tagNumber: 2 // dNSName
          },
          value: [
            new asn1.Utf8String({ value: dnsName })
          ]
        })
      );
      
      extensions.push(
        new asn1.Sequence({
          value: [
            new asn1.ObjectIdentifier({ value: '2.5.29.17' }), // subjectAltName OID
            new asn1.Boolean({ value: false }),
            new asn1.OctetString({
              valueHex: new asn1.Sequence({
                value: generalNames
              }).toBER()
            })
          ]
        })
      );
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
        
        // 颁发者 (CA)
        createName(caSubject),
        
        // 有效期
        new asn1.Sequence({
          value: [
            new asn1.UTCTime({ value: dateToASN1(notBefore) }),
            new asn1.UTCTime({ value: dateToASN1(notAfter) })
          ]
        }),
        
        // 主题 (服务器)
        createName(serverSubject),
        
        // 主题公钥信息
        new asn1.fromBER(publicKeyBuffer.buffer).result,
        
        // 扩展
        new asn1.Constructed({
          idBlock: {
            tagClass: 3,
            tagNumber: 3
          },
          value: [
            new asn1.Sequence({
              value: extensions
            })
          ]
        })
      ]
    });
    
    const certificatePEM = await generateCertificate(tbsCertificate, caKeyPair);
    console.log('✓ 服务器证书生成成功');
    return certificatePEM;
    
  } catch (error) {
    console.error('生成服务器证书时出错:', error);
    throw error;
  }
}

/**
 * 验证密钥对
 */
async function verifyKeyPair(keyPair) {
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
 * 保存密钥和证书到文件
 */
async function saveToFile(privateKeyPEM, publicKeyPEM, certificatePEM, baseName) {
  try {
    await writeFile(`${baseName}_private.pem`, privateKeyPEM);
    await writeFile(`${baseName}_public.pem`, publicKeyPEM);
    await writeFile(`${baseName}_certificate.pem`, certificatePEM);
    console.log(`✓ 文件已保存: ${baseName}_private.pem, ${baseName}_public.pem, ${baseName}_certificate.pem`);
  } catch (error) {
    console.error('保存文件时出错:', error);
    throw error;
  }
}

/**
 * 生成证书链文件
 */
async function saveCertificateChain(rootCert, intermediateCert, serverCert, filename = 'certificate_chain.pem') {
  try {
    const chain = rootCert + '\n' + intermediateCert + '\n' + serverCert;
    await writeFile(filename, chain);
    console.log(`✓ 证书链已保存: ${filename}`);
  } catch (error) {
    console.error('保存证书链时出错:', error);
    throw error;
  }
}

/**
 * 主函数 - 完整的 PKI 系统
 */
async function main() {
  try {
    console.log('=== 完整的 Ed25519 PKI 系统 ===\n');
    
    // 1. 生成根 CA
    console.log('步骤 1: 生成根 CA');
    const rootKeyPair = await generateEd25519KeyPair();
    const rootSubject = {
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'My Root CA Company',
      OU: 'Certificate Authority',
      CN: 'My Root CA'
    };
    const rootCertificatePEM = await generateRootCACertificate(rootKeyPair, rootSubject);
    const rootPrivateKeyPEM = await exportPrivateKeyToPEM(rootKeyPair.privateKey);
    const rootPublicKeyPEM = await exportPublicKeyToPEM(rootKeyPair.publicKey);
    await saveToFile(rootPrivateKeyPEM, rootPublicKeyPEM, rootCertificatePEM, 'root_ca');
    console.log('✓ 根 CA 生成完成\n');
    
    // 2. 生成中间 CA
    console.log('步骤 2: 生成中间 CA');
    const intermediateKeyPair = await generateEd25519KeyPair();
    const intermediateSubject = {
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'My Intermediate CA Company',
      OU: 'Intermediate Certificate Authority',
      CN: 'My Intermediate CA'
    };
    const intermediateCertificatePEM = await generateIntermediateCACertificate(
      intermediateKeyPair, 
      rootKeyPair, 
      rootSubject, 
      intermediateSubject
    );
    const intermediatePrivateKeyPEM = await exportPrivateKeyToPEM(intermediateKeyPair.privateKey);
    const intermediatePublicKeyPEM = await exportPublicKeyToPEM(intermediateKeyPair.publicKey);
    await saveToFile(intermediatePrivateKeyPEM, intermediatePublicKeyPEM, intermediateCertificatePEM, 'intermediate_ca');
    console.log('✓ 中间 CA 生成完成\n');
    
    // 3. 生成服务器证书
    console.log('步骤 3: 生成服务器证书');
    const serverKeyPair = await generateEd25519KeyPair();
    const serverSubject = {
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'My Server Company',
      OU: 'IT Department',
      CN: 'server.example.com'
    };
    const serverCertificatePEM = await generateServerCertificate(
      serverKeyPair,
      intermediateKeyPair, // 使用中间 CA 签发
      intermediateSubject,
      serverSubject,
      ['server.example.com', 'www.example.com', 'localhost'] // SAN 列表
    );
    const serverPrivateKeyPEM = await exportPrivateKeyToPEM(serverKeyPair.privateKey);
    const serverPublicKeyPEM = await exportPublicKeyToPEM(serverKeyPair.publicKey);
    await saveToFile(serverPrivateKeyPEM, serverPublicKeyPEM, serverCertificatePEM, 'server');
    console.log('✓ 服务器证书生成完成\n');
    
    // 4. 生成证书链
    console.log('步骤 4: 生成证书链');
    await saveCertificateChain(rootCertificatePEM, intermediateCertificatePEM, serverCertificatePEM);
    console.log('✓ 证书链生成完成\n');
    
    // 5. 验证所有密钥对
    console.log('步骤 5: 验证密钥对');
    const rootValid = await verifyKeyPair(rootKeyPair);
    const intermediateValid = await verifyKeyPair(intermediateKeyPair);
    const serverValid = await verifyKeyPair(serverKeyPair);
    
    if (rootValid && intermediateValid && serverValid) {
      console.log('✓ 所有密钥对验证成功');
    } else {
      console.log('✗ 部分密钥对验证失败');
      return;
    }
    
    // 输出总结
    console.log('\n=== PKI 系统生成完成 ===');
    console.log('生成的文件:');
    console.log('  - root_ca_private.pem (根 CA 私钥 - 请安全保存)');
    console.log('  - root_ca_public.pem (根 CA 公钥)');
    console.log('  - root_ca_certificate.pem (根 CA 证书)');
    console.log('  - intermediate_ca_private.pem (中间 CA 私钥)');
    console.log('  - intermediate_ca_public.pem (中间 CA 公钥)');
    console.log('  - intermediate_ca_certificate.pem (中间 CA 证书)');
    console.log('  - server_private.pem (服务器私钥)');
    console.log('  - server_public.pem (服务器公钥)');
    console.log('  - server_certificate.pem (服务器证书)');
    console.log('  - certificate_chain.pem (完整证书链)');
    
    console.log('\n证书层级:');
    console.log('  根 CA (10年) → 中间 CA (5年) → 服务器证书 (1年)');
    
  } catch (error) {
    console.error('\n程序执行出错:', error);
    process.exit(1);
  }
}

// 运行程序
main();