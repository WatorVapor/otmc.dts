// openssl-ca-class.js
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { TBSRequest } from 'pkijs';
import { fileURLToPath } from 'url';

// 在 ES6 模块中获取 __dirname 的等价物
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default class OpenSSLCA {
  constructor(baseDir = './pki') {
    this.trace = false;
    this.debug = true;
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
  createRootCA(rootCert,subject,validityYears = 10,rootKey) {
    try {
      console.log('Creating Root CA...');
      
      const certSubject = this.createOpenSSLConfig(subject);
      console.log(`OpenSSLCA::createRootCA::certSubject:=<`, certSubject, '>');
      
      const sslCmd = `openssl req -new -x509 -days ${validityYears*365} -key ${rootKey} ` +
        `-subj "${certSubject}" `+
        `-sha256 -extensions v3_ca -out ${rootCert}`;
      console.log(`OpenSSLCA::createRootCA::sslCmd:=<`, sslCmd, '>');
      // 自签名根证书
      const result = execSync(sslCmd);
      console.log(`OpenSSLCA::createRootCA::result:=<`, result.toString(), '>');
      
      console.log(`Root CA created successfully:`);
      console.log(`  Certificate: ${rootCert}`);
      console.log(`  Private Key: ${rootKey}`);
      
      return { certificate: rootCert, privateKey: rootKey };
    } catch (error) {
      throw new Error(`Failed to create Root CA: ${error.message}`);
    }
  }

  /**
   * 创建服务器证书
   */
  createServerCert(serverCert,subject, validityYears,serverKey,caKey,caCert) {
    if(this.trace) {
      console.log(`OpenSSLCA::createServerCert::serverCert:=<`, serverCert, '>');
      console.log(`OpenSSLCA::createServerCert::subject:=<`, subject, '>');
      console.log(`OpenSSLCA::createServerCert::validityYears:=<`, validityYears, '>');
      console.log(`OpenSSLCA::createServerCert::serverKey:=<`, serverKey, '>');
      console.log(`OpenSSLCA::createServerCert::caKey:=<`, caKey, '>');
      console.log(`OpenSSLCA::createServerCert::caCert:=<`, caCert, '>');
    }

    try {      
      const certSubject = this.createOpenSSLConfig(subject);
      console.log(`OpenSSLCA::createServerCert::certSubject:=<`, certSubject, '>');

      const serverCSR = serverCert.replace('.crt', '.csr.pem');
      console.log(`OpenSSLCA::createServerCert::serverCSR:=<`, serverCSR, '>');
      
      
      // 生成CSR
      let sslCmd = `openssl req -new -sha256 -key ${serverKey} ` +
        `-out ${serverCSR} -subj "${certSubject}"`;
      console.log(`OpenSSLCA::createServerCert::sslCmd:=<`, sslCmd, '>');
      execSync(sslCmd);
      
      // 使用CA签名服务器证书
      sslCmd = `openssl x509 -req -CA ${caCert} -CAkey ${caKey} ` +
        `-CAcreateserial ` +
        `-days ${validityYears*365} -sha256 ` +
        `-in ${serverCSR} -out ${serverCert}`;
      console.log(`OpenSSLCA::createServerCert::sslCmd:=<`, sslCmd, '>');
      execSync(sslCmd);
      
      console.log(`Server certificate created successfully:`);
      console.log(`  Certificate: ${serverCert}`);
      console.log(`  Private Key: ${serverKey}`);
      
      return { certificate: serverCert, privateKey: serverKey };
    } catch (error) {
      throw new Error(`Failed to create server certificate: ${error.message}`);
    }
  }

  /**
   * 创建服务器CSR
   */
  createServerCSR(serverCSR,subject, validityYears,serverKey) {
    if(this.trace) {
      console.log(`OpenSSLCA::createServerCSR::serverCSR:=<`, serverCSR, '>');
      console.log(`OpenSSLCA::createServerCSR::subject:=<`, subject, '>');
      console.log(`OpenSSLCA::createServerCSR::validityYears:=<`, validityYears, '>');
      console.log(`OpenSSLCA::createServerCSR::serverKey:=<`, serverKey, '>');
    }

    try {      
      const certSubject = this.createOpenSSLConfig(subject);
      console.log(`OpenSSLCA::createServerCert::certSubject:=<`, certSubject, '>');     
      
      // 生成CSR
      let sslCmd = `openssl req -new -sha256 -key ${serverKey} ` +
        `-out ${serverCSR} -subj "${certSubject}"`;
      console.log(`OpenSSLCA::createServerCert::sslCmd:=<`, sslCmd, '>');
      execSync(sslCmd);
      
      
      return { csr: serverCSR, privateKey: serverKey };
    } catch (error) {
      throw new Error(`Failed to create server certificate: ${error.message}`);
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
