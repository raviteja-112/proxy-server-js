const http = require("http");
const net = require("net");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PROXY_PORT = 8080;
const BLOCKLIST_FILE = "blocklist.txt";

// Logging function
function logActivity(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;
  console.log(logMessage);
  fs.appendFile("proxy-log.txt", logMessage, (err) => {
    if (err) console.error("Error writing to log file:", err.message);
  });
}

// Load the blocklist
function loadBlocklist() {
  const blocklistPath = path.join(__dirname, BLOCKLIST_FILE);
  try {
    const data = fs.readFileSync(blocklistPath, "utf-8");
    const blocklist = data
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    logActivity(`Blocklist loaded: ${blocklist.join(", ")}`);
    return blocklist;
  } catch (err) {
    logActivity(`Error loading blocklist: ${err.message}`);
    return [];
  }
}

// Create HTTP proxy server
const server = http.createServer((req, res) => {
  const clientIP = req.socket.remoteAddress;
  const { method, url } = req;

  try {
    const targetUrl = new URL(url);
    const hostname = targetUrl.hostname;

    const blocklist = loadBlocklist();
    if (blocklist.includes(hostname)) {
      logActivity(`Blocked HTTP request from ${clientIP} to ${hostname}`);
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Access to this website is blocked by the proxy.");
      return;
    }

    logActivity(`HTTP request from ${clientIP}: ${method} ${targetUrl.href}`);

    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || 80,
      path: targetUrl.pathname + targetUrl.search,
      method,
      headers: req.headers,
    };

    const proxyReq = http.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on("error", (err) => {
      logActivity(`Error in HTTP proxy request from ${clientIP}: ${err.message}`);
      res.writeHead(500);
      res.end("Proxy encountered an error.");
    });

    req.pipe(proxyReq);
  } catch (err) {
    logActivity(`Invalid URL from ${clientIP}: ${url}`);
    res.writeHead(400);
    res.end("Bad Request: Invalid URL.");
  }
});

// Handle CONNECT requests for HTTPS
server.on("connect", (req, clientSocket, head) => {
    const clientIP = clientSocket.remoteAddress;
    const { host } = req.headers; // e.g., 'www.google.com:443'
    const [hostname, port] = host.split(":");
  
    logActivity(`CONNECT request from ${clientIP} to ${host}`);
  
    const blocklist = loadBlocklist();
  
    // Check if the hostname is in the blocklist
    logActivity(`Checking if ${hostname} is in blocklist: ${blocklist.includes(hostname)}`);
    if (blocklist.includes(hostname)) {
      logActivity(`Blocked CONNECT request from ${clientIP} to ${hostname}`);
      clientSocket.write(
        "HTTP/1.1 403 Forbidden\r\n" +
          "Content-Type: text/plain\r\n" +
          "\r\n" +
          "Access to this website is blocked by the proxy.\r\n"
      );
      clientSocket.end();
      return;
    }
  
    // Proceed with the connection
    const serverSocket = net.connect(port || 443, hostname, () => {
      clientSocket.write(
        "HTTP/1.1 200 Connection Established\r\n" +
          "Proxy-agent: Node.js-Proxy\r\n" +
          "\r\n"
      );
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });
  
    serverSocket.on("error", (err) => {
      logActivity(`Error in HTTPS tunnel from ${clientIP}: ${err.message}`);
      clientSocket.end();
    });
  
    clientSocket.on("error", (err) => {
      logActivity(`Client socket error from ${clientIP}: ${err.message}`);
    });
  });



// Log connection and disconnection events
server.on("connection", (socket) => {
  const clientIP = socket.remoteAddress;
  logActivity(`New connection from ${clientIP}`);
  socket.on("close", () => {
    logActivity(`Connection closed by ${clientIP}`);
  });
  socket.on("error", (err) => {
    logActivity(`Socket error from ${clientIP}: ${err.message}`);
  });
});

// Handle server errors
server.on("error", (err) => {
  logActivity(`Server error: ${err.message}`);
});

// Start the server
server.listen(PROXY_PORT, () => {
  logActivity(`HTTPS Proxy Server running on port ${PROXY_PORT}`);
});
