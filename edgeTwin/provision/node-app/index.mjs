import http from 'http';
import { execSync } from 'child_process';
import { unlink } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import express from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Unix socket 文件路径
const socketPath = '/dev/shm/otmc.dts.provision.factor.sock';

// 创建 HTTP 服务器
const server = http.createServer((req, res) => {
  // 已由 Express 接管，此处逻辑删除
});

// 使用 Express 框架重构
const app = express();

// 解析 JSON 请求体
app.use(express.json());

// 定义 POST /provision/add/client/cert 路由
app.post('/provision/add/client/cert', (req, res) => {
  try {
    const data = req.body;
    // 这里简单返回收到的数据，实际业务可在此处理证书逻辑
    res.status(200).json({ success: true, received: data });
  } catch (err) {
    res.status(400).send('Invalid JSON\n');
  }
});

app.get('/provision/add/client/cert', (req, res) => {
  try {
    const data = req.body;
    // 这里简单返回收到的数据，实际业务可在此处理证书逻辑
    res.status(200).json({ success: true, received: data });
  } catch (err) {
    res.status(400).send('Invalid JSON\n');
  }
});

// 404 处理
app.use((req, res) => {
  res.status(404).send('Not Found\n');
});

// 将 Express 应用挂载到原 server
server.on('request', app);

// 启动前清理已存在的 socket 文件
try {
  await unlink(socketPath);
} catch (err) {
  // 文件不存在时忽略错误
}

// 监听 Unix socket
server.listen(socketPath, () => {
  console.log(`HTTP 服务器已启动，监听 Unix socket: ${socketPath}`);
  execSync('chmod 777 /dev/shm/otmc.dts.provision.factor.sock');
});

// 优雅退出时清理 socket 文件
process.on('SIGINT', async () => {
  console.log('\n收到 SIGINT，正在关闭服务器并清理 socket 文件...');
  server.close(async () => {
    try {
      await unlink(socketPath);
      console.log('socket 文件已清理，进程退出');
    } catch (err) {
      console.error('清理 socket 文件失败:', err);
    }
    process.exit(0);
  });
});
