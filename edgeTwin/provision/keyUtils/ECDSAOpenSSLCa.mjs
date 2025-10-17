// openssl-ca-class.js
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// 在 ES6 模块中获取 __dirname 的等价物
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default class OpenSSLCA {
  constructor(baseDir = './pki') {
    this.baseDir = baseDir;
    this.opensslConfig = {
      rootCaConfig: path.join(this.baseDir, 'root_CA.cnf'),
      intermediateCaConfig: path.join(this.baseDir, 'intermediate_CA.cnf')
    };
    
    this.initDirectories();
  }

  /**
   * 初始化CA目录结构
   */
  initDirectories() {
    const dirs = [
      this.baseDir,
      path.join(this.baseDir, 'rootCA'),
      path.join(this.baseDir, 'rootCA/certs'),
      path.join(this.baseDir, 'rootCA/crl'),
      path.join(this.baseDir, 'rootCA/newcerts'),
      path.join(this.baseDir, 'rootCA/private'),
      path.join(this.baseDir, 'intermediateCA'),
      path.join(this.baseDir, 'intermediateCA/certs'),
      path.join(this.baseDir, 'intermediateCA/crl'),
      path.join(this.baseDir, 'intermediateCA/newcerts'),
      path.join(this.baseDir, 'intermediateCA/private'),
      path.join(this.baseDir, 'client-certs')
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`Created directory: ${dir}`);
      }
    });

    // 初始化跟踪文件
    const rootIndex = path.join(this.baseDir, 'rootCA/index.txt');
    const rootSerial = path.join(this.baseDir, 'rootCA/serial');
    const intermediateIndex = path.join(this.baseDir, 'intermediateCA/index.txt');
    const intermediateSerial = path.join(this.baseDir, 'intermediateCA/serial');

    if (!fs.existsSync(rootIndex)) fs.writeFileSync(rootIndex, '');
    if (!fs.existsSync(rootSerial)) fs.writeFileSync(rootSerial, '1000');
    if (!fs.existsSync(intermediateIndex)) fs.writeFileSync(intermediateIndex, '');
    if (!fs.existsSync(intermediateSerial)) fs.writeFileSync(intermediateSerial, '1000');

    // 设置权限
    this.setPermissions();
  }

  /**
   * 设置目录权限
   */
  setPermissions() {
    try {
      if (process.platform !== 'win32') {
        execSync(`chmod 700 ${path.join(this.baseDir, 'rootCA/private')}`);
        execSync(`chmod 700 ${path.join(this.baseDir, 'intermediateCA/private')}`);
      }
    } catch (error) {
      console.warn('Warning: Could not set permissions:', error.message);
    }
  }

  /**
   * 生成ECDSA密钥对
   * @param {string} outputKey - 输出私钥文件路径
   * @param {string} curve - 椭圆曲线名称 (prime256v1, secp384r1, secp521r1)
   * @param {boolean} pkcs8 - 是否转换为PKCS8格式
   */
  generateECDSAKeyPair(outputKey, curve = 'prime256v1', pkcs8 = true) {
    try {
      console.log(`Generating ECDSA key pair with curve ${curve}...`);
      
      // 生成原始ECDSA私钥
      const tempKey = outputKey.replace('.pem', '_temp.pem');
      console.log(`OpenSSLCA::generateECDSAKeyPair::tempKey:=<`, tempKey, '>');
      const result1 = execSync(`openssl ecparam -name ${curve} -genkey -noout -out ${tempKey}`);
      console.log(`OpenSSLCA::generateECDSAKeyPair::result1:=<`, result1.toString(), '>');
      
      let finalKey = outputKey;
      
      if (pkcs8) {
        // 转换为PKCS8格式
        execSync(`openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ${tempKey} -out ${finalKey}`);
        fs.unlinkSync(tempKey);
      } else {
        fs.renameSync(tempKey, finalKey);
      }
      
      // 生成对应的公钥
      const pubKey = outputKey.replace('.pem', '_pub.pem');
      execSync(`openssl ec -in ${finalKey} -pubout -out ${pubKey}`);
      
      console.log(`ECDSA key pair generated successfully:`);
      console.log(`  Private Key: ${finalKey}`);
      console.log(`  Public Key: ${pubKey}`);
      
      return { privateKey: finalKey, publicKey: pubKey };
    } catch (error) {
      throw new Error(`Failed to generate ECDSA key pair: ${error.message}`);
    }
  }
  /**
   * 从私钥创建公钥
   * @param {string} privateKey - 私钥文件路径
   * @param {string} publicKey - 公钥文件路径
   */
  createPublicKeyFromPrivateKey(privateKey, publicKey) {
    try {
      console.log(`Creating public key from private key...`);
      execSync(`openssl ec -in ${privateKey} -pubout -out ${publicKey}`);
      console.log(`Public key created successfully: ${publicKey}`);
      return publicKey;
    } catch (error) {
      throw new Error(`Failed to create public key from private key: ${error.message}`);
    }
  }

  /**
   * 创建OpenSSL配置文件
   */
  createOpenSSLConfig(subject) {
    console.log(`OpenSSLCA::createOpenSSLConfig::subject:=<`, subject, '>');
    const certConfig = `/C=${subject.C}/ST=${subject.ST}/L=${subject.L}/O=${subject.O}/OU=${subject.OU}/CN=${subject.CN}`;
    return certConfig;
  }

  /**
   * 创建根CA
   */
  createRootCA(rootCert,subject,validityYears = 3650,rootKey) {
    try {
      console.log('Creating Root CA...');
      
      const certSubject = this.createOpenSSLConfig(subject);
      console.log(`OpenSSLCA::createRootCA::certSubject:=<`, certSubject, '>');
      
      // 自签名根证书
      execSync(`openssl req -new -x509 -days ${validityYears} -key ${rootKey} ` +
        `-sha256 -extensions v3_ca -out ${rootCert} ` +
        `-subj "${certSubject}"`);
      
      console.log(`Root CA created successfully:`);
      console.log(`  Certificate: ${rootCert}`);
      console.log(`  Private Key: ${rootKey}`);
      
      return { certificate: rootCert, privateKey: rootKey };
    } catch (error) {
      throw new Error(`Failed to create Root CA: ${error.message}`);
    }
  }

  /**
   * 创建中间CA
   */
  createIntermediateCA(curve = 'prime256v1') {
    try {
      console.log('Creating Intermediate CA...');
      
      const intermediateKey = path.join(this.baseDir, 'intermediateCA/private/intermediate_ca.key.pem');
      const intermediateCSR = path.join(this.baseDir, 'intermediateCA/certs/intermediate_ca.csr.pem');
      const intermediateCert = path.join(this.baseDir, 'intermediateCA/certs/intermediate_ca.cert.pem');
      const rootKey = path.join(this.baseDir, 'rootCA/private/root_ca.key.pem');
      const rootCert = path.join(this.baseDir, 'rootCA/certs/root_ca.cert.pem');
      
      // 检查根CA是否存在
      if (!fs.existsSync(rootKey) || !fs.existsSync(rootCert)) {
        throw new Error('Root CA not found. Please create Root CA first.');
      }
      
      // 生成中间CA密钥对
      this.generateECDSAKeyPair(curve, intermediateKey);
      
      // 生成中间CA的证书签名请求(CSR)
      execSync(`openssl req -new -sha256 -key ${intermediateKey} ` +
        `-out ${intermediateCSR} -config ${this.opensslConfig.intermediateCaConfig}`);
      
      // 使用根CA签名中间证书
      execSync(`openssl ca -batch -config ${this.opensslConfig.rootCaConfig} ` +
        `-extensions v3_intermediate_ca -days 1825 -notext -md sha256 ` +
        `-in ${intermediateCSR} -out ${intermediateCert}`);
      
      // 创建证书链
      const chainCert = path.join(this.baseDir, 'intermediateCA/certs/ca-chain.cert.pem');
      const intermediateCertContent = fs.readFileSync(intermediateCert);
      const rootCertContent = fs.readFileSync(rootCert);
      fs.writeFileSync(chainCert, intermediateCertContent + rootCertContent);
      
      console.log(`Intermediate CA created successfully:`);
      console.log(`  Certificate: ${intermediateCert}`);
      console.log(`  Private Key: ${intermediateKey}`);
      console.log(`  Certificate Chain: ${chainCert}`);
      
      return {
        certificate: intermediateCert,
        privateKey: intermediateKey,
        chain: chainCert
      };
    } catch (error) {
      throw new Error(`Failed to create Intermediate CA: ${error.message}`);
    }
  }

  /**
   * 生成服务器证书
   */
  generateServerCert(commonName, curve = 'prime256v1', san = null) {
    try {
      console.log(`Generating Server Certificate for: ${commonName}`);
      
      const serverKey = path.join(this.baseDir, `client-certs/${commonName}.key.pem`);
      const serverCSR = path.join(this.baseDir, `client-certs/${commonName}.csr.pem`);
      const serverCert = path.join(this.baseDir, `client-certs/${commonName}.cert.pem`);
      const intermediateKey = path.join(this.baseDir, 'intermediateCA/private/intermediate_ca.key.pem');
      const intermediateCert = path.join(this.baseDir, 'intermediateCA/certs/intermediate_ca.cert.pem');
      
      // 检查中间CA是否存在
      if (!fs.existsSync(intermediateKey) || !fs.existsSync(intermediateCert)) {
        throw new Error('Intermediate CA not found. Please create Intermediate CA first.');
      }
      
      // 生成服务器密钥对
      this.generateECDSAKeyPair(curve, serverKey);
      
      // 创建自定义配置文件（如果需要SAN）
      let configArgs = '';
      if (san) {
        const sanConfig = this.createSANConfig(commonName, san);
        configArgs = `-config ${sanConfig}`;
      }
      
      // 生成CSR
      execSync(`openssl req -new -sha256 -key ${serverKey} ` +
        `-out ${serverCSR} ${configArgs} -subj "/CN=${commonName}"`);
      
      // 使用中间CA签名服务器证书
      execSync(`openssl ca -batch -config ${this.opensslConfig.intermediateCaConfig} ` +
        `-extensions server_cert -days 375 -notext -md sha256 ` +
        `-in ${serverCSR} -out ${serverCert}`);
      
      console.log(`Server certificate generated successfully:`);
      console.log(`  Certificate: ${serverCert}`);
      console.log(`  Private Key: ${serverKey}`);
      
      return { certificate: serverCert, privateKey: serverKey };
    } catch (error) {
      throw new Error(`Failed to generate server certificate: ${error.message}`);
    }
  }

  /**
   * 创建SAN配置
   */
  createSANConfig(commonName, san) {
    const sanConfig = `
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = ${commonName}

[req_ext]
subjectAltName = @alt_names

[alt_names]
${san.map((entry, index) => `DNS.${index + 1} = ${entry}`).join('\n')}
`;
    
    const configPath = path.join(this.baseDir, `client-certs/${commonName}_san.cnf`);
    fs.writeFileSync(configPath, sanConfig);
    return configPath;
  }

  /**
   * 验证证书
   */
  verifyCertificate(certPath, caChainPath) {
    try {
      const output = execSync(`openssl verify -CAfile ${caChainPath} ${certPath}`).toString();
      console.log(`Certificate verification: ${output}`);
      return output.includes('OK');
    } catch (error) {
      console.error(`Certificate verification failed: ${error.message}`);
      return false;
    }
  }

  /**
   * 显示证书信息
   */
  displayCertificateInfo(certPath) {
    try {
      const output = execSync(`openssl x509 -in ${certPath} -text -noout`).toString();
      console.log(`Certificate Information for ${certPath}:\n${output}`);
      return output;
    } catch (error) {
      console.error(`Failed to display certificate information: ${error.message}`);
      return null;
    }
  }

  /**
   * 清理临时文件
   */
  cleanup() {
    try {
      // 删除临时配置文件
      if (fs.existsSync(this.opensslConfig.rootCaConfig)) {
        fs.unlinkSync(this.opensslConfig.rootCaConfig);
      }
      if (fs.existsSync(this.opensslConfig.intermediateCaConfig)) {
        fs.unlinkSync(this.opensslConfig.intermediateCaConfig);
      }
      
      // 查找并删除所有SAN配置文件
      const sanConfigs = fs.readdirSync(path.join(this.baseDir, 'client-certs'))
        .filter(file => file.endsWith('_san.cnf'));
      
      sanConfigs.forEach(file => {
        fs.unlinkSync(path.join(this.baseDir, 'client-certs', file));
      });
      
      console.log('Temporary files cleaned up successfully');
    } catch (error) {
      console.warn('Warning: Could not clean up temporary files:', error.message);
    }
  }
}
