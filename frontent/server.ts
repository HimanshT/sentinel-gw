import express from "express";
import { createServer as createViteServer } from "vite";
import { createProxyMiddleware } from "http-proxy-middleware";
import { WebSocketServer, WebSocket } from "ws";
import { GoogleGenAI, Type } from "@google/genai";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Configuration
let config = {
  backendUrl: "https://jsonplaceholder.typicode.com", // Default backend for demo
  rateLimit: 10, // requests per minute per IP
  aiThreshold: 0.7, // 0-1, higher means more sensitive
  blockedIps: [] as string[],
  whitelistIps: [] as string[],
  aiEnabled: true,
};

// State
const logs: any[] = [];
const ipRequests = new Map<string, { count: number; lastReset: number }>();

// AI Setup
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

// WebSocket for real-time updates
const wss = new WebSocketServer({ noServer: true });
const clients = new Set<WebSocket>();

wss.on("connection", (ws) => {
  clients.add(ws);
  ws.on("close", () => clients.delete(ws));
});

function broadcast(data: any) {
  const message = JSON.stringify(data);
  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Middleware for AI and Security
app.use(express.json());

app.get("/api/config", (req, res) => res.json(config));
app.post("/api/config", (req, res) => {
  config = { ...config, ...req.body };
  res.json(config);
});

app.get("/api/logs", (req, res) => res.json(logs.slice(-100).reverse()));

app.get("/api/stats", (req, res) => {
  const total = logs.length;
  const blocked = logs.filter((l) => l.status === "blocked").length;
  const allowed = total - blocked;
  res.json({ total, blocked, allowed });
});

// Security Engine
async function securityEngine(req: express.Request, res: express.Response, next: express.NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();

  // 1. Firewall (IP check)
  if (config.blockedIps.includes(ip)) {
    logRequest(req, "blocked", "Firewall: IP Blocked");
    return res.status(403).json({ error: "Access Denied (IP Blocked)" });
  }

  if (config.whitelistIps.length > 0 && !config.whitelistIps.includes(ip)) {
    logRequest(req, "blocked", "Firewall: Not in Whitelist");
    return res.status(403).json({ error: "Access Denied (Not Whitelisted)" });
  }

  // 2. Rate Limiting
  const ipData = ipRequests.get(ip) || { count: 0, lastReset: now };
  if (now - ipData.lastReset > 60000) {
    ipData.count = 1;
    ipData.lastReset = now;
  } else {
    ipData.count++;
  }
  ipRequests.set(ip, ipData);

  if (ipData.count > config.rateLimit) {
    logRequest(req, "blocked", "Rate Limit Exceeded");
    return res.status(429).json({ error: "Too Many Requests" });
  }

  // 3. AI Threat Detection
  let aiResult = { isThreat: false, score: 0, reason: "N/A" };
  if (config.aiEnabled && req.path.startsWith("/proxy")) {
    try {
      const prompt = `Analyze this API request for security threats (SQL injection, XSS, brute force, anomalous headers). 
      Return JSON: { "isThreat": boolean, "score": number (0-1), "reason": string, "category": string }
      Request:
      Method: ${req.method}
      Path: ${req.path}
      Headers: ${JSON.stringify(req.headers)}
      Body: ${JSON.stringify(req.body)}
      `;

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              isThreat: { type: Type.BOOLEAN },
              score: { type: Type.NUMBER },
              reason: { type: Type.STRING },
              category: { type: Type.STRING },
            },
            required: ["isThreat", "score", "reason", "category"],
          },
        },
      });

      const result = JSON.parse(response.text || "{}");
      aiResult = result;

      if (result.isThreat && result.score >= config.aiThreshold) {
        logRequest(req, "blocked", `AI: ${result.reason}`, result);
        return res.status(403).json({ error: `Access Denied (AI Flagged: ${result.reason})` });
      }
    } catch (err) {
      console.error("AI Analysis Error:", err);
      // Fail open or closed? Let's fail open for demo but log it
    }
  }

  logRequest(req, "allowed", "Passed Security Checks", aiResult);
  next();
}

function logRequest(req: express.Request, status: "allowed" | "blocked", reason: string, aiData?: any) {
  const log = {
    id: Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    ip: req.ip || req.socket.remoteAddress || "unknown",
    method: req.method,
    path: req.path,
    status,
    reason,
    aiScore: aiData?.score || 0,
    aiCategory: aiData?.category || "N/A",
  };
  logs.push(log);
  if (logs.length > 1000) logs.shift();
  broadcast({ type: "NEW_LOG", log });
}

// Proxy Middleware
const proxy = createProxyMiddleware({
  target: config.backendUrl,
  router: () => config.backendUrl,
  changeOrigin: true,
  pathRewrite: {
    "^/proxy": "", // remove /proxy prefix when sending to backend
  },
});

// Apply security to proxy routes
app.use("/proxy", securityEngine, proxy);

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res, next) => {
      if (req.path.startsWith("/api") || req.path.startsWith("/proxy")) {
        return next();
      }
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`Gateway running at http://localhost:${PORT}`);
    console.log(`Proxying /proxy/* to ${config.backendUrl}`);
  });

  server.on("upgrade", (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit("connection", ws, request);
    });
  });
}

startServer();
