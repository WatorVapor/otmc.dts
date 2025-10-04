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
 * 创建简单的根 CA 证书 (简化版本)
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
    
    // 构建简化的 TBS 证书结构
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
        
        // 主题公钥信息 - 直接使用导出的 SPKI
        new asn1.fromBER(publicKeyBuffer.buffer).result,
        
        // 扩展 - 简化处理
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
                    new asn1.ObjectIdentifier({ value: '2.5.29.19' }), // basicConstraints OID
                    new asn1.Boolean({ value: true }), // critical
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
                    new asn1.ObjectIdentifier({ value: '2.5.29.15' }), // keyUsage OID
                    new asn1.Boolean({ value: true }), // critical
                    new asn1.OctetString({
                      valueHex: new asn1.BitString({
                        valueHex: new Uint8Array([0x03, 0x05]) // keyCertSign + cRLSign
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
    
    // 对 TBS 证书进行签名
    const tbsBuffer = tbsCertificate.toBER();
    const signature = await subtle.sign(
      'Ed25519',
      keyPair.privateKey,
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
    
    console.log('✓ 根 CA 证书生成成功');
    return pem;
    
  } catch (error) {
    console.error('生成根 CA 证书时出错:', error);
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
async function saveToFile(privateKeyPEM, publicKeyPEM, certificatePEM, baseName = 'root_ca') {
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
 * 主函数
 */
async function main() {
  try {
    console.log('=== Ed25519 根 CA 证书生成器 ===\n');
    
    // 生成密钥对
    console.log('正在生成 Ed25519 密钥对...');
    const keyPair = await generateEd25519KeyPair();
    console.log('✓ 密钥对生成成功');
    
    // 验证密钥对
    console.log('正在验证密钥对...');
    const isValid = await verifyKeyPair(keyPair);
    if (!isValid) {
      console.log('✗ 密钥对验证失败');
      return;
    }
    console.log('✓ 密钥对验证成功');
    
    // 导出密钥
    console.log('正在导出密钥...');
    const privateKeyPEM = await exportPrivateKeyToPEM(keyPair.privateKey);
    const publicKeyPEM = await exportPublicKeyToPEM(keyPair.publicKey);
    console.log('✓ 密钥导出成功');
    
    // 生成根 CA 证书
    const subject = {
      C: 'CN',
      ST: 'Beijing',
      L: 'Beijing',
      O: 'My Company',
      OU: 'IT Department',
      CN: 'My Root CA'
    };
    
    const certificatePEM = await generateRootCACertificate(keyPair, subject);
    
    // 输出结果
    console.log('\n=== 生成的根 CA ===\n');
    
    console.log('私钥:');
    console.log(privateKeyPEM);
    
    console.log('公钥:');
    console.log(publicKeyPEM);
    
    console.log('根 CA 证书:');
    console.log(certificatePEM);
    
    // 保存到文件
    await saveToFile(privateKeyPEM, publicKeyPEM, certificatePEM);
    
    console.log('\n=== 完成 ===');
    
  } catch (error) {
    console.error('\n程序执行出错:', error);
    process.exit(1);
  }
}

// 运行程序
main();