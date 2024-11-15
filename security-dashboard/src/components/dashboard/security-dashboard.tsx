'use client'

import React, { useState, useEffect, useRef } from 'react';
import { Shield, Box, Terminal, Network, ChevronRight, Wifi, Radio, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from "@/components/ui/progress";

// Types
interface BattleLog {
  id: string;
  message: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'alert' | 'critical';
  source_ip: string;
}

// System Status Component
const SystemStatus = () => {
  const [metrics, setMetrics] = useState({
    cpu_percent: 45,
    memory_percent: 62,
    disk_usage: 78,
    network_bytes_sent: 1024 * 1024 * 2, // 2MB
    network_bytes_recv: 1024 * 1024 * 5, // 5MB
    memory_used: 1024 * 1024 * 1024 * 8, // 8GB
    memory_total: 1024 * 1024 * 1024 * 16, // 16GB
    disk_used: 1024 * 1024 * 1024 * 1024 * 0.8, // 0.8TB
    disk_total: 1024 * 1024 * 1024 * 1024, // 1TB
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(prev => ({
        cpu_percent: Math.min(100, Math.max(0, prev.cpu_percent + (Math.random() * 20 - 10))),
        memory_percent: Math.min(100, Math.max(0, prev.memory_percent + (Math.random() * 10 - 5))),
        disk_usage: Math.min(100, Math.max(0, prev.disk_usage + (Math.random() * 2 - 1))),
        network_bytes_sent: Math.max(0, prev.network_bytes_sent + (Math.random() * 1024 * 1024 * 2)),
        network_bytes_recv: Math.max(0, prev.network_bytes_recv + (Math.random() * 1024 * 1024 * 3)),
        memory_used: prev.memory_used + (Math.random() * 1024 * 1024 * 100),
        memory_total: prev.memory_total,
        disk_used: prev.disk_used + (Math.random() * 1024 * 1024 * 50),
        disk_total: prev.disk_total,
      }));
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
          <Box className="h-4 w-4 text-cyan-500" />
          SYSTEM STATUS
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-4">
          <div className="relative">
            <div className="flex justify-between items-center mb-2">
              <span className="text-xs font-mono text-zinc-300">CPU USAGE</span>
              <span className="text-xs font-mono text-cyan-500">{metrics.cpu_percent.toFixed(1)}%</span>
            </div>
            <Progress value={metrics.cpu_percent} className="h-1" />
          </div>

          <div className="relative">
            <div className="flex justify-between items-center mb-2">
              <span className="text-xs font-mono text-zinc-300">MEMORY</span>
              <span className="text-xs font-mono text-cyan-500">{metrics.memory_percent.toFixed(1)}%</span>
            </div>
            <Progress value={metrics.memory_percent} className="h-1" />
            <div className="text-[10px] font-mono text-zinc-500 mt-1">
              {formatBytes(metrics.memory_used)} / {formatBytes(metrics.memory_total)}
            </div>
          </div>

          <div className="relative">
            <div className="flex justify-between items-center mb-2">
              <span className="text-xs font-mono text-zinc-300">DISK USAGE</span>
              <span className="text-xs font-mono text-cyan-500">{metrics.disk_usage.toFixed(1)}%</span>
            </div>
            <Progress value={metrics.disk_usage} className="h-1" />
            <div className="text-[10px] font-mono text-zinc-500 mt-1">
              {formatBytes(metrics.disk_used)} / {formatBytes(metrics.disk_total)}
            </div>
          </div>

          <div className="relative">
            <div className="flex justify-between items-center mb-2">
              <span className="text-xs font-mono text-zinc-300">NETWORK I/O</span>
              <span className="text-xs font-mono text-cyan-500">
                ↑{formatBytes(metrics.network_bytes_sent)}/s
              </span>
            </div>
            <Progress value={75} className="h-1" />
            <div className="text-[10px] font-mono text-zinc-500 mt-1">
              ↓{formatBytes(metrics.network_bytes_recv)}/s
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// Code Viewer Component
const CodeViewer = () => {
  const [currentCode, setCurrentCode] = useState<string>('');
  const [isTyping, setIsTyping] = useState(false);
  const [allCode, setAllCode] = useState<string[]>([]);
  const typeTimeoutRef = useRef<NodeJS.Timeout>();

  const SAMPLE_CODE = `### Shell Commands to Patch Ubuntu 14.04 System

\`\`\`bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get install --only-upgrade openssh-server -y
sudo ufw enable
sudo ufw default deny incoming
sudo ufw allow ssh
sudo passwd --lock root
sudo usermod -L root
sudo apt-get autoremove -y
sudo apt-get autoclean -y
\`\`\``;

  useEffect(() => {
    animateNewCode(SAMPLE_CODE);
    return () => {
      if (typeTimeoutRef.current) {
        clearTimeout(typeTimeoutRef.current);
      }
    };
  }, []);

  const animateNewCode = (code: string) => {
    setIsTyping(true);
    let index = 0;
    setCurrentCode('');
    
    const typeCode = () => {
      if (index < code.length) {
        setCurrentCode(code.slice(0, index + 1));
        index++;
        typeTimeoutRef.current = setTimeout(typeCode, Math.random() * 30 + 20);
      } else {
        setIsTyping(false);
        setAllCode([code]);
      }
    };
    
    typeCode();
  };

  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-mono text-zinc-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-500" />
            LIVE DEFENSE GENERATION
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-[10px] px-2 py-1 rounded ${isTyping ? 'bg-cyan-500/10 text-cyan-500 animate-pulse' : 'bg-zinc-800 text-zinc-400'}`}>
              {isTyping ? 'GENERATING DEFENSE' : 'MONITORING'}
            </span>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="bg-black/50 rounded-lg p-4 border border-zinc-800">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-500" />
                <span className="text-xs font-mono text-zinc-400">
                  DEFENSE CODE
                </span>
              </div>
            </div>
            <pre className="bg-black rounded p-2 overflow-x-auto min-h-[200px] max-h-[600px] overflow-y-auto">
              <code className="text-xs font-mono text-cyan-500 whitespace-pre-wrap">
                {currentCode || allCode.join('\n\n') || '// Awaiting defense code...'}
              </code>
            </pre>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// Main Command Center Component
const CommandCenter = () => {
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected'>('connected');
  const [currentTime, setCurrentTime] = useState<string>(new Date().toLocaleTimeString());
  const [battleLogs, setBattleLogs] = useState<BattleLog[]>([
    {
      id: '1',
      message: 'Port scan detected from suspicious IP',
      timestamp: new Date().toISOString(),
      severity: 'warning',
      source_ip: '192.168.1.100'
    },
    {
      id: '2',
      message: 'Brute force SSH attempt blocked',
      timestamp: new Date().toISOString(),
      severity: 'alert',
      source_ip: '10.0.0.50'
    },
    {
      id: '3',
      message: 'System firewall rules updated',
      timestamp: new Date().toISOString(),
      severity: 'info',
      source_ip: 'system'
    }
  ]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const possibleLogs = [
      {
        message: 'Unauthorized access attempt blocked',
        severity: 'warning',
        source_ip: '192.168.1.150'
      },
      {
        message: 'Critical security patch applied',
        severity: 'info',
        source_ip: 'system'
      },
      {
        message: 'DDoS attack detected and mitigated',
        severity: 'alert',
        source_ip: '10.0.0.25'
      },
      {
        message: 'System breach detected - implementing countermeasures',
        severity: 'critical',
        source_ip: '172.16.0.100'
      },
      {
        message: 'Malware signature updated',
        severity: 'info',
        source_ip: 'system'
      },
      {
        message: 'Suspicious outbound connection blocked',
        severity: 'warning',
        source_ip: '192.168.1.75'
      }
    ];

    const interval = setInterval(() => {
      const randomLog = possibleLogs[Math.floor(Math.random() * possibleLogs.length)];
      const newLog = {
        id: Date.now().toString(),
        timestamp: new Date().toISOString(),
        ...randomLog
      } as BattleLog;

      setBattleLogs(prev => [newLog, ...prev].slice(0, 20));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const renderBattleLogs = () => {
    if (!battleLogs || battleLogs.length === 0) {
      return (
        <div className="text-xs font-mono text-zinc-500 text-center py-4">
          No logs available
        </div>
      );
    }

    return battleLogs.map((log) => (
      <div key={log.id} className="flex items-start gap-2 pb-2 border-b border-zinc-800">
        <ChevronRight className={`h-4 w-4 ${
          log.severity === 'critical' ? 'text-red-500' :
          log.severity === 'alert' ? 'text-amber-500' :
          log.severity === 'warning' ? 'text-yellow-500' :
          'text-cyan-500'
        }`} />
        <div>
          <div className="text-xs font-mono text-zinc-300">
            {log.message}
          </div>
          <div className="text-[10px] font-mono text-zinc-500 flex gap-2">
            <span>{new Date(log.timestamp).toLocaleString()}</span>
            <span>|</span>
            <span>IP: {log.source_ip}</span>
          </div>
        </div>
      </div>
    ));
  };

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      {/* Top Bar */}
      <div className="flex justify-between items-center mb-8 border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-4">
          <div className="h-10 w-1 bg-cyan-500" />
          <div>
            <h1 className="text-3xl font-mono tracking-tight text-zinc-100">C2 DEFENDER</h1>
            <div className="flex items-center gap-2 mt-1">
              <div className={`h-2 w-2 rounded-full animate-pulse ${
                connectionStatus === 'connected' ? 'bg-cyan-500' : 'bg-red-500'
              }`} />
              <p className="text-xs font-mono text-zinc-400 tracking-widest">
                OPERATIONAL STATUS: {connectionStatus.toUpperCase()}
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex flex-col items-end">
            <div className="text-xs font-mono text-zinc-400">SYSTEM TIME</div>
            <div className="text-sm font-mono text-cyan-500">{currentTime}</div>
          </div>
          <div className="flex gap-2">
            <Wifi className={`h-5 w-5 ${connectionStatus === 'connected' ? 'text-cyan-500' : 'text-red-500'}`} />
            <Radio className="h-5 w-5 text-cyan-500 animate-pulse" />
          </div>
        </div>
      </div>

      {/* Main Grid */}
      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-6">
        {/* Left Column - System Status */}
        <div className="col-span-3">
          <SystemStatus />
        </div>

        {/* Center Column - Code Viewer */}
        <div className="col-span-6">
          <CodeViewer />
        </div>

        {/* Right Column - Network Status & Defense Status */}
        <div className="col-span-3 space-y-6">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
                <Network className="h-4 w-4 text-cyan-500" />
                NETWORK STATUS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">MAIN SENSOR</span>
                  <span className="text-xs font-mono text-emerald-500">ACTIVE</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">DEFENSE GRID</span>
                  <span className="text-xs font-mono text-emerald-500">ONLINE</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">COMMAND LINK</span>
                  <span className="text-xs font-mono text-emerald-500">CONNECTED</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-500" />
                DEFENSE STATUS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">FIREWALL</span>
                  <span className="text-xs font-mono text-emerald-500">ACTIVE</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">IDS/IPS</span>
                  <span className="text-xs font-mono text-emerald-500">MONITORING</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">ENCRYPTION</span>
                  <span className="text-xs font-mono text-emerald-500">ENABLED</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono text-zinc-300">BACKUP</span>
                  <span className="text-xs font-mono text-yellow-500">SCHEDULED</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Battle Logs Card */}
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-500" />
                BATTLE LOG {battleLogs.length > 0 && `(${battleLogs.length})`}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 max-h-[400px] overflow-y-auto">
                {renderBattleLogs()}
              </div>
            </CardContent>
          </Card>

          {/* Active Connections Card */}
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
                <Network className="h-4 w-4 text-cyan-500" />
                ACTIVE CONNECTIONS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="text-2xl font-mono text-cyan-500">
                  {connectionStatus === 'connected' ? 'ONLINE' : 'OFFLINE'}
                </div>
                <div className="text-xs font-mono text-zinc-400">
                  Last Updated: {currentTime}
                </div>
                <div className="mt-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <div className={`h-2 w-2 rounded-full ${connectionStatus === 'connected' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                    <span className="text-xs font-mono text-zinc-300">Main Sensor Array</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`h-2 w-2 rounded-full ${connectionStatus === 'connected' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                    <span className="text-xs font-mono text-zinc-300">Defense Grid</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`h-2 w-2 rounded-full ${connectionStatus === 'connected' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                    <span className="text-xs font-mono text-zinc-300">Command Link</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Critical Alert Banner */}
      {battleLogs.some(log => log.severity === 'critical' || log.severity === 'alert') && (
        <Alert className="bg-red-950/30 border-red-900/50 text-red-200 mt-6">
          <AlertTriangle className="h-4 w-4 text-red-500" />
          <AlertDescription className="text-xs font-mono ml-2">
            CRITICAL: ACTIVE THREATS DETECTED - DEFENSE PROTOCOLS ENGAGED
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};

export default CommandCenter;