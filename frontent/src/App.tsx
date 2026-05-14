import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Activity, 
  Settings, 
  Lock, 
  Unlock, 
  AlertTriangle, 
  Terminal, 
  Cpu, 
  Globe, 
  RefreshCw,
  Trash2,
  Plus,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Clock
} from "lucide-react";
import { 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area
} from "recharts";
import { motion, AnimatePresence } from "motion/react";
import { format } from "date-fns";
import { cn } from "./lib/utils";

interface Log {
  id: string;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  status: "allowed" | "blocked";
  reason: string;
  aiScore: number;
  aiCategory: string;
}

interface Config {
  backendUrl: string;
  rateLimit: number;
  aiThreshold: number;
  blockedIps: string[];
  whitelistIps: string[];
  aiEnabled: boolean;
}

interface Stats {
  total: number;
  blocked: number;
  allowed: number;
}

export default function App() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const [stats, setStats] = useState<Stats>({ total: 0, blocked: 0, allowed: 0 });
  const [activeTab, setActiveTab] = useState<"dashboard" | "logs" | "config">("dashboard");
  const [isSaving, setIsSaving] = useState(false);
  const [testUrl, setTestUrl] = useState("/proxy/posts/1");
  const [testResult, setTestResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    fetchConfig();
    fetchLogs();
    fetchStats();
    const interval = setInterval(() => {
      fetchLogs();
      fetchStats();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const fetchConfig = async () => {
    const res = await fetch("/api/config");
    const data = await res.json();
    setConfig(data);
  };

  const fetchLogs = async () => {
    const res = await fetch("/api/logs");
    const data = await res.json();
    setLogs(data.slice(0, 100));
  };

  const fetchStats = async () => {
    const res = await fetch("/api/stats");
    const data = await res.json();
    setStats(data);
  };

  const saveConfig = async (newConfig: Config) => {
    setIsSaving(true);
    try {
      await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newConfig),
      });
      setConfig(newConfig);
    } finally {
      setIsSaving(false);
    }
  };

  const runTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const backendEnvironment = (import.meta as any).env?.VITE_BACKEND_URL;
      const backendBase = config?.backendUrl || backendEnvironment || `${window.location.protocol}//${window.location.hostname}:8000`;
      const normalizedBackendBase = backendBase.replace(/\/+$/, "");
      let requestUrl: string;

      if (testUrl.startsWith("/proxy")) {
        requestUrl = `${normalizedBackendBase}${testUrl.replace(/^\/proxy/, "/test")}`;
      } else if (testUrl.startsWith("/test")) {
        requestUrl = `${normalizedBackendBase}${testUrl}`;
      } else {
        requestUrl = new URL(testUrl, window.location.origin).href;
      }
      const res = await fetch(requestUrl);
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
      setTestResult({ status: res.status, data });
    } catch (err: any) {
      setTestResult({ status: "Error", data: err.message });
    } finally {
      setIsTesting(false);
    }
  };

  // Chart data preparation
  const chartData = logs.slice(0, 20).reverse().map(l => ({
    time: format(new Date(l.timestamp), "HH:mm:ss"),
    score: l.aiScore * 100,
    status: l.status === "allowed" ? 1 : 0
  }));

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-white font-sans selection:bg-blue-500/30">
      {/* Sidebar */}
      <div className="fixed left-0 top-0 bottom-0 w-64 border-r border-white/5 bg-[#0D0D0E] z-50 hidden md:block">
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-600/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-tight text-white">Sentinel</h1>
            <p className="text-[10px] text-white/40 uppercase tracking-widest font-semibold">API Gateway</p>
          </div>
        </div>

        <nav className="mt-8 px-4 space-y-2">
          <NavItem 
            active={activeTab === "dashboard"} 
            onClick={() => setActiveTab("dashboard")}
            icon={<Activity className="w-4 h-4" />}
            label="Dashboard"
          />
          <NavItem 
            active={activeTab === "logs"} 
            onClick={() => setActiveTab("logs")}
            icon={<Terminal className="w-4 h-4" />}
            label="Traffic Logs"
          />
          <NavItem 
            active={activeTab === "config"} 
            onClick={() => setActiveTab("config")}
            icon={<Settings className="w-4 h-4" />}
            label="Configuration"
          />
        </nav>

        <div className="absolute bottom-8 left-6 right-6">
          <div className="p-4 rounded-2xl bg-white/5 border border-white/5">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-xs font-medium text-white/60">System Online</span>
            </div>
            <p className="text-[10px] text-white/40 leading-relaxed">
              AI-Powered threat detection active. Monitoring real-time traffic.
            </p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="md:ml-64 p-8">
        <header className="flex items-center justify-between mb-10">
          <div>
            <h2 className="text-3xl font-bold tracking-tight mb-1">
              {activeTab === "dashboard" && "Network Overview"}
              {activeTab === "logs" && "Traffic Analysis"}
              {activeTab === "config" && "Gateway Settings"}
            </h2>
            <p className="text-white/40 text-sm">
              {activeTab === "dashboard" && "Real-time security metrics and traffic patterns."}
              {activeTab === "logs" && "Detailed inspection of all incoming API requests."}
              {activeTab === "config" && "Manage firewall, rate limits, and AI sensitivity."}
            </p>
          </div>

          <div className="flex items-center gap-4">
            <button 
              onClick={() => { fetchStats(); fetchLogs(); }}
              className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors border border-white/5 cursor-pointer"
            >
              <RefreshCw className="w-4 h-4 text-white/60" />
            </button>
            <div className="h-8 w-[1px] bg-white/10 mx-2" />
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20">
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              <span className="text-xs font-medium text-blue-400">Gemini 3.1 Flash</span>
            </div>
          </div>
        </header>

        <AnimatePresence mode="wait">
          {activeTab === "dashboard" && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-8"
            >
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <StatCard 
                  label="Total Requests" 
                  value={stats.total} 
                  sub="Last 24 hours"
                  icon={<Globe className="w-5 h-5 text-blue-400" />}
                  color="blue"
                />
                <StatCard 
                  label="Blocked Threats" 
                  value={stats.blocked} 
                  sub={`${((stats.blocked / (stats.total || 1)) * 100).toFixed(1)}% block rate`}
                  icon={<Lock className="w-5 h-5 text-red-400" />}
                  color="red"
                />
                <StatCard 
                  label="Allowed Traffic" 
                  value={stats.allowed} 
                  sub="Verified clean requests"
                  icon={<Unlock className="w-5 h-5 text-green-400" />}
                  color="green"
                />
              </div>

              {/* Charts Section */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="p-6 rounded-3xl bg-[#0D0D0E] border border-white/5">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Activity className="w-4 h-4 text-blue-400" />
                      AI Threat Score Trend
                    </h3>
                    <span className="text-[10px] text-white/40 uppercase tracking-widest font-bold">Real-time</span>
                  </div>
                  <div className="h-[250px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData}>
                        <defs>
                          <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                        <XAxis 
                          dataKey="time" 
                          stroke="#ffffff20" 
                          fontSize={10} 
                          tickLine={false} 
                          axisLine={false}
                        />
                        <YAxis 
                          stroke="#ffffff20" 
                          fontSize={10} 
                          tickLine={false} 
                          axisLine={false}
                          domain={[0, 100]}
                        />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#151516', border: '1px solid #ffffff10', borderRadius: '12px', fontSize: '12px' }}
                          itemStyle={{ color: '#fff' }}
                        />
                        <Area 
                          type="monotone" 
                          dataKey="score" 
                          stroke="#3b82f6" 
                          fillOpacity={1} 
                          fill="url(#colorScore)" 
                          strokeWidth={2}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="p-6 rounded-3xl bg-[#0D0D0E] border border-white/5">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-purple-400" />
                      Quick Test Tool
                    </h3>
                  </div>
                  <div className="space-y-4">
                    <div className="flex gap-2">
                      <div className="flex-1 relative">
                        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40 text-xs font-mono">GET</div>
                        <input 
                          type="text" 
                          value={testUrl}
                          onChange={(e) => setTestUrl(e.target.value)}
                          className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-12 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all font-mono text-white"
                          placeholder="/proxy/your-endpoint or http://localhost:8000/test/your-endpoint"
                        />
                      </div>
                      <button 
                        onClick={runTest}
                        disabled={isTesting}
                        className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 shadow-lg shadow-blue-600/20 cursor-pointer"
                      >
                        {isTesting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                        Send
                      </button>
                    </div>
                    
                    <div className="p-4 rounded-2xl bg-black/40 border border-white/5 h-[160px] overflow-auto font-mono text-xs">
                      {testResult ? (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <span className="text-white/40">Status:</span>
                            <span className={cn(
                              "font-bold",
                              testResult.status >= 400 ? "text-red-400" : "text-green-400"
                            )}>{testResult.status}</span>
                          </div>
                          <pre className="text-white/60 whitespace-pre-wrap">
                            {JSON.stringify(testResult.data, null, 2)}
                          </pre>
                        </div>
                      ) : (
                        <div className="h-full flex items-center justify-center text-white/20 italic">
                          Response will appear here...
                        </div>
                      )}
                    </div>
                    <p className="text-[10px] text-white/30 italic">
                      Tip: Try adding malicious payloads like <code className="text-red-400/60">?id=' OR 1=1</code> to test AI detection.
                    </p>
                  </div>
                </div>
              </div>

              {/* Recent Activity Mini Table */}
              <div className="p-6 rounded-3xl bg-[#0D0D0E] border border-white/5">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold">Recent Traffic</h3>
                  <button onClick={() => setActiveTab("logs")} className="text-xs text-blue-400 hover:underline cursor-pointer">View all logs</button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="text-white/40 border-b border-white/5">
                        <th className="pb-3 font-medium">Timestamp</th>
                        <th className="pb-3 font-medium">Method</th>
                        <th className="pb-3 font-medium">Path</th>
                        <th className="pb-3 font-medium">Status</th>
                        <th className="pb-3 font-medium">AI Score</th>
                        <th className="pb-3 font-medium">Reason</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {logs.slice(0, 5).map((log) => (
                        <tr key={log.id} className="group hover:bg-white/[0.02] transition-colors">
                          <td className="py-4 text-white/60 text-xs font-mono">
                            {format(new Date(log.timestamp), "HH:mm:ss")}
                          </td>
                          <td className="py-4">
                            <span className="px-2 py-0.5 rounded bg-white/5 text-[10px] font-bold uppercase tracking-wider text-white/60">
                              {log.method}
                            </span>
                          </td>
                          <td className="py-4 font-mono text-xs text-white/80">{log.path}</td>
                          <td className="py-4">
                            <div className={cn(
                              "flex items-center gap-1.5 text-xs font-medium",
                              log.status === "allowed" ? "text-green-400" : "text-red-400"
                            )}>
                              {log.status === "allowed" ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                              {log.status}
                            </div>
                          </td>
                          <td className="py-4">
                            <div className="flex items-center gap-2">
                              <div className="w-12 h-1.5 bg-white/5 rounded-full overflow-hidden">
                                <div 
                                  className={cn(
                                    "h-full rounded-full",
                                    log.aiScore > 0.7 ? "bg-red-500" : log.aiScore > 0.4 ? "bg-yellow-500" : "bg-blue-500"
                                  )}
                                  style={{ width: `${log.aiScore * 100}%` }}
                                />
                              </div>
                              <span className="text-[10px] text-white/40">{(log.aiScore * 100).toFixed(0)}%</span>
                            </div>
                          </td>
                          <td className="py-4 text-xs text-white/40 truncate max-w-[200px]">{log.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "logs" && (
            <motion.div 
              key="logs"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="p-6 rounded-3xl bg-[#0D0D0E] border border-white/5"
            >
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-4">
                  <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20">
                    <Terminal className="w-5 h-5 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-bold">Traffic Logs</h3>
                </div>
                <div className="flex gap-2">
                   <button className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-medium hover:bg-white/10 transition-all cursor-pointer">Export CSV</button>
                   <button onClick={() => setLogs([])} className="px-4 py-2 rounded-xl bg-red-500/10 border border-red-500/20 text-xs font-medium text-red-400 hover:bg-red-500/20 transition-all cursor-pointer">Clear Logs</button>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="text-white/40 border-b border-white/5">
                      <th className="pb-4 font-medium">Timestamp</th>
                      <th className="pb-4 font-medium">IP Address</th>
                      <th className="pb-4 font-medium">Request</th>
                      <th className="pb-4 font-medium">AI Analysis</th>
                      <th className="pb-4 font-medium">Status</th>
                      <th className="pb-4 font-medium">Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {logs.map((log) => (
                      <tr key={log.id} className="group hover:bg-white/[0.02] transition-colors">
                        <td className="py-5">
                          <div className="flex flex-col">
                            <span className="text-white/80 font-medium">{format(new Date(log.timestamp), "HH:mm:ss")}</span>
                            <span className="text-[10px] text-white/30">{format(new Date(log.timestamp), "MMM dd, yyyy")}</span>
                          </div>
                        </td>
                        <td className="py-5">
                          <code className="text-xs text-blue-400/80 bg-blue-400/5 px-2 py-1 rounded-md">{log.ip}</code>
                        </td>
                        <td className="py-5">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded bg-white/5 text-[9px] font-black uppercase text-white/40 border border-white/5">
                              {log.method}
                            </span>
                            <span className="text-xs font-mono text-white/70">{log.path}</span>
                          </div>
                        </td>
                        <td className="py-5">
                          <div className="flex flex-col gap-1">
                            <div className="flex items-center gap-2">
                              <span className={cn(
                                "text-[10px] font-bold px-1.5 py-0.5 rounded",
                                log.aiScore > 0.7 ? "bg-red-500/10 text-red-400" : "bg-blue-500/10 text-blue-400"
                              )}>
                                {log.aiCategory}
                              </span>
                              <span className="text-[10px] text-white/40">{(log.aiScore * 100).toFixed(0)}% threat</span>
                            </div>
                          </div>
                        </td>
                        <td className="py-5">
                          <span className={cn(
                            "px-2 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider",
                            log.status === "allowed" ? "bg-green-500/10 text-green-400 border border-green-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"
                          )}>
                            {log.status}
                          </span>
                        </td>
                        <td className="py-5 text-xs text-white/50 italic">{log.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {activeTab === "config" && config && (
            <motion.div 
              key="config"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="grid grid-cols-1 lg:grid-cols-3 gap-8"
            >
              <div className="lg:col-span-2 space-y-8">
                {/* Core Settings */}
                <div className="p-8 rounded-3xl bg-[#0D0D0E] border border-white/5 space-y-6">
                  <div className="flex items-center gap-4 mb-2">
                    <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/20">
                      <Settings className="w-5 h-5 text-blue-400" />
                    </div>
                    <h3 className="text-xl font-bold">Core Configuration</h3>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-white/40 uppercase tracking-wider">Backend Target URL</label>
                      <input 
                        type="text" 
                        value={config.backendUrl}
                        onChange={(e) => setConfig({...config, backendUrl: e.target.value})}
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all text-white"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-white/40 uppercase tracking-wider">Rate Limit (Req/Min)</label>
                      <input 
                        type="number" 
                        value={config.rateLimit}
                        onChange={(e) => setConfig({...config, rateLimit: parseInt(e.target.value)})}
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all text-white"
                      />
                    </div>
                  </div>

                  <div className="pt-4 flex items-center justify-between p-4 rounded-2xl bg-white/[0.02] border border-white/5">
                    <div className="flex items-center gap-3">
                      <div className={cn(
                        "p-2 rounded-lg transition-colors",
                        config.aiEnabled ? "bg-blue-500/20 text-blue-400" : "bg-white/5 text-white/20"
                      )}>
                        <Cpu className="w-5 h-5" />
                      </div>
                      <div>
                        <p className="text-sm font-semibold">AI Threat Detection</p>
                        <p className="text-xs text-white/40">Use Gemini to analyze request payloads</p>
                      </div>
                    </div>
                    <button 
                      onClick={() => setConfig({...config, aiEnabled: !config.aiEnabled})}
                      className={cn(
                        "w-12 h-6 rounded-full relative transition-all duration-300 cursor-pointer",
                        config.aiEnabled ? "bg-blue-600" : "bg-white/10"
                      )}
                    >
                      <div className={cn(
                        "absolute top-1 w-4 h-4 rounded-full bg-white transition-all duration-300",
                        config.aiEnabled ? "left-7" : "left-1"
                      )} />
                    </button>
                  </div>

                  {config.aiEnabled && (
                    <div className="space-y-4 pt-2">
                      <div className="flex items-center justify-between">
                        <label className="text-xs font-semibold text-white/40 uppercase tracking-wider">AI Sensitivity Threshold</label>
                        <span className="text-sm font-mono text-blue-400">{(config.aiThreshold * 100).toFixed(0)}%</span>
                      </div>
                      <input 
                        type="range" 
                        min="0" 
                        max="1" 
                        step="0.05"
                        value={config.aiThreshold}
                        onChange={(e) => setConfig({...config, aiThreshold: parseFloat(e.target.value)})}
                        className="w-full h-1.5 bg-white/10 rounded-lg appearance-none cursor-pointer accent-blue-600"
                      />
                      <div className="flex justify-between text-[10px] text-white/20 font-bold uppercase">
                        <span>Lenient</span>
                        <span>Strict</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* IP Management */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <IPList 
                    title="Blocked IPs" 
                    ips={config.blockedIps} 
                    onUpdate={(ips) => setConfig({...config, blockedIps: ips})}
                    icon={<Lock className="w-4 h-4 text-red-400" />}
                  />
                  <IPList 
                    title="Whitelisted IPs" 
                    ips={config.whitelistIps} 
                    onUpdate={(ips) => setConfig({...config, whitelistIps: ips})}
                    icon={<Unlock className="w-4 h-4 text-green-400" />}
                  />
                </div>
              </div>

              <div className="space-y-6">
                <div className="p-6 rounded-3xl bg-blue-600/10 border border-blue-500/20">
                  <h4 className="font-bold mb-2 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-blue-400" />
                    Deployment Info
                  </h4>
                  <p className="text-xs text-white/60 leading-relaxed mb-4">
                    Changes to configuration are applied instantly to the gateway engine. No restart required.
                  </p>
                  <button 
                    onClick={() => saveConfig(config)}
                    disabled={isSaving}
                    className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-xl font-bold text-sm transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 cursor-pointer"
                  >
                    {isSaving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                    Save Configuration
                  </button>
                </div>

                <div className="p-6 rounded-3xl bg-white/[0.02] border border-white/5">
                  <h4 className="font-bold mb-4 text-sm">Security Best Practices</h4>
                  <ul className="space-y-3">
                    <li className="flex gap-3 text-xs text-white/40">
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1 shrink-0" />
                      Keep AI threshold above 0.7 to minimize false positives.
                    </li>
                    <li className="flex gap-3 text-xs text-white/40">
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1 shrink-0" />
                      Use whitelisting for internal admin APIs.
                    </li>
                    <li className="flex gap-3 text-xs text-white/40">
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1 shrink-0" />
                      Regularly review logs for new attack patterns.
                    </li>
                  </ul>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

function NavItem({ active, onClick, icon, label }: { active: boolean, onClick: () => void, icon: React.ReactNode, label: string }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all cursor-pointer",
        active 
          ? "bg-blue-600/10 text-blue-400 border border-blue-500/20 shadow-sm" 
          : "text-white/40 hover:text-white/60 hover:bg-white/5 border border-transparent"
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function StatCard({ label, value, sub, icon, color }: { label: string, value: number, sub: string, icon: React.ReactNode, color: "blue" | "red" | "green" }) {
  const colors = {
    blue: "from-blue-500/20 to-transparent border-blue-500/20",
    red: "from-red-500/20 to-transparent border-red-500/20",
    green: "from-green-500/20 to-transparent border-green-500/20"
  };

  return (
    <div className={cn(
      "p-6 rounded-3xl bg-gradient-to-br border relative overflow-hidden group",
      colors[color]
    )}>
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="p-2 rounded-xl bg-white/5 border border-white/5">
            {icon}
          </div>
          <span className="text-[10px] font-bold text-white/20 uppercase tracking-widest">Live</span>
        </div>
        <h3 className="text-3xl font-bold tracking-tight mb-1">{value.toLocaleString()}</h3>
        <p className="text-xs font-medium text-white/40">{label}</p>
        <div className="mt-4 pt-4 border-t border-white/5 flex items-center gap-2">
          <Clock className="w-3 h-3 text-white/20" />
          <span className="text-[10px] text-white/30 font-medium">{sub}</span>
        </div>
      </div>
      <div className="absolute -right-4 -bottom-4 w-24 h-24 bg-white/[0.02] rounded-full blur-2xl group-hover:bg-white/[0.05] transition-all duration-500" />
    </div>
  );
}

function IPList({ title, ips, onUpdate, icon }: { title: string, ips: string[], onUpdate: (ips: string[]) => void, icon: React.ReactNode }) {
  const [newIp, setNewIp] = useState("");

  const addIp = () => {
    if (newIp && !ips.includes(newIp)) {
      onUpdate([...ips, newIp]);
      setNewIp("");
    }
  };

  const removeIp = (ip: string) => {
    onUpdate(ips.filter(i => i !== ip));
  };

  return (
    <div className="p-6 rounded-3xl bg-[#0D0D0E] border border-white/5 space-y-4">
      <div className="flex items-center justify-between">
        <h4 className="font-bold text-sm flex items-center gap-2">
          {icon}
          {title}
        </h4>
        <span className="text-[10px] font-mono text-white/30 bg-white/5 px-2 py-0.5 rounded">{ips.length} entries</span>
      </div>
      
      <div className="flex gap-2">
        <input 
          type="text" 
          value={newIp}
          onChange={(e) => setNewIp(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addIp()}
          placeholder="Add IP address..."
          className="flex-1 bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all font-mono text-white"
        />
        <button 
          onClick={addIp}
          className="p-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-all cursor-pointer"
        >
          <Plus className="w-4 h-4" />
        </button>
      </div>

      <div className="space-y-2 max-h-[150px] overflow-auto pr-2 custom-scrollbar">
        {ips.map(ip => (
          <div key={ip} className="flex items-center justify-between p-2 rounded-xl bg-white/[0.02] border border-white/5 group">
            <span className="text-xs font-mono text-white/60">{ip}</span>
            <button 
              onClick={() => removeIp(ip)}
              className="p-1 text-white/20 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
        {ips.length === 0 && (
          <div className="py-8 text-center text-xs text-white/20 italic">
            List is empty
          </div>
        )}
      </div>
    </div>
  );
}
