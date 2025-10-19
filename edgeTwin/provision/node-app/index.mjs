import http from 'http';
import { execSync } from 'child_process';
import { unlink } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Unix socket 文件路径
const socketPath = '/dev/shm/otmc.dts.provision.factor.sock';

// 创建 HTTP 服务器
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Hello from Unix socket HTTP server!\n');
});

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
