'use client'

import React, { useState, useEffect, useRef } from 'react';
import { Shield, Cpu, Activity, AlertTriangle, TrendingUp, Radio, Target, CrosshairIcon, ShieldAlert, Terminal, Network, ChevronRight, Wifi, Box } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from "@/components/ui/progress";
import CodeViewer from './CodeViewer';

// Types
interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  disk_usage: number;
  network_bytes_sent: number;
  network_bytes_recv: number;
  timestamp?: string;
  memory_used?: number;
  memory_total?: number;
  disk_used?: number;
  disk_total?: number;
}

interface BattleLog {
  message: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'alert' | 'critical';
}

interface DefenseAction {
  id: string;
  timestamp: string;
  type: 'firewall' | 'ids' | 'authentication' | 'encryption';
  code: string;
  status: 'active' | 'pending' | 'completed';
  description: string;
}

// Dummy data
const dummyMetrics: SystemMetrics = {
  cpu_percent: 45,
  memory_percent: 60,
  disk_usage: 75,
  network_bytes_sent: 1024 * 1024 * 50,
  network_bytes_recv: 1024 * 1024 * 30,
  memory_used: 8 * 1024 * 1024 * 1024,
  memory_total: 16 * 1024 * 1024 * 1024,
  disk_used: 256 * 1024 * 1024 * 1024,
  disk_total: 512 * 1024 * 1024 * 1024
};

const dummyLogs: BattleLog[] = [
  {
    message: "System startup initiated",
    timestamp: new Date().toISOString(),
    severity: "info"
  },
  {
    message: "Suspicious login attempt detected",
    timestamp: new Date().toISOString(),
    severity: "warning"
  },
  {
    message: "Firewall rules updated",
    timestamp: new Date().toISOString(),
    severity: "info"
  }
];

const dummyDefenseActions: DefenseAction[] = [
  {
    id: '1',
    timestamp: new Date().toISOString(),
    type: 'firewall',
    status: 'active',
    description: 'Updating firewall rules to block suspicious IP range',
    code: `iptables -A INPUT -s 192.168.1.0/24 -j DROP
iptables -A OUTPUT -d 192.168.1.0/24 -j DROP
systemctl restart firewalld`
  },
  {
    id: '2',
    timestamp: new Date().toISOString(),
    type: 'ids',
    status: 'completed',
    description: 'Updated Snort rules for SQL injection detection',
    code: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"SQL Injection Attempt";
  flow:to_server,established;
  content:"UNION SELECT"; nocase;
  sid:1000001; rev:1;
)`
  }
];

const CommandCenter = () => {
  // State
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>(dummyMetrics);
  const [battleLogs, setBattleLogs] = useState<BattleLog[]>(dummyLogs);
  const [defenseActions, setDefenseActions] = useState<DefenseAction[]>(dummyDefenseActions);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected'>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const [currentTime, setCurrentTime] = useState<string>(new Date().toLocaleTimeString());

  // Update time
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // WebSocket connection
  useEffect(() => {
    const connectWebSocket = () => {
      try {
        const ws = new WebSocket('ws://localhost:8000/ws');
        wsRef.current = ws;

        ws.onopen = () => {
          console.log('WebSocket Connected');
          setConnectionStatus('connected');
        };

        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          
          switch (data.type) {
            case 'system_metrics':
              setSystemMetrics(data.data);
              break;
            case 'battle_logs':
              setBattleLogs(data.data);
              break;
            case 'defense_actions':
              setDefenseActions(data.data);
              break;
          }
        };

        ws.onclose = () => {
          console.log('WebSocket Disconnected');
          setConnectionStatus('disconnected');
          setTimeout(connectWebSocket, 5000);
        };

        ws.onerror = (error) => {
          console.error('WebSocket Error:', error);
          setConnectionStatus('disconnected');
          ws.close();
        };
      } catch (error) {
        console.error('WebSocket Connection Error:', error);
        setConnectionStatus('disconnected');
      }
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Fetch initial data
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const metricsResponse = await fetch('http://localhost:8000/system-metrics');
        if (metricsResponse.ok) {
          const metricsData = await metricsResponse.json();
          setSystemMetrics(metricsData);
        }
      } catch (error) {
        console.error('Error fetching initial data:', error);
      }
    };

    fetchInitialData();
  }, []);

  // Format bytes
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
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
      <div className="grid grid-cols-12 gap-6">
        {/* Left Column - System Status */}
        <div className="col-span-3 space-y-6">
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
                    <span className="text-xs font-mono text-cyan-500">{systemMetrics.cpu_percent}%</span>
                  </div>
                  <Progress value={systemMetrics.cpu_percent} className="h-1" />
                </div>

                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">MEMORY</span>
                    <span className="text-xs font-mono text-cyan-500">{systemMetrics.memory_percent}%</span>
                  </div>
                  <Progress value={systemMetrics.memory_percent} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">
                    {formatBytes(systemMetrics.memory_used || 0)} / {formatBytes(systemMetrics.memory_total || 0)}
                  </div>
                </div>

                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">DISK USAGE</span>
                    <span className="text-xs font-mono text-cyan-500">{systemMetrics.disk_usage}%</span>
                  </div>
                  <Progress value={systemMetrics.disk_usage} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">
                    {formatBytes(systemMetrics.disk_used || 0)} / {formatBytes(systemMetrics.disk_total || 0)}
                  </div>
                </div>

                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">NETWORK I/O</span>
                    <span className="text-xs font-mono text-cyan-500">
                      ↑{formatBytes(systemMetrics.network_bytes_sent)}/s
                    </span>
                  </div>
                  <Progress value={75} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">
                    ↓{formatBytes(systemMetrics.network_bytes_recv)}/s
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Center Column - Main Display */}
        <div className="col-span-6 space-y-6">
          {battleLogs.some(log => log.severity === 'critical') && (
            <Alert className="bg-red-950/30 border-red-900/50 text-red-200">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <AlertDescription className="text-xs font-mono ml-2">
                CRITICAL: ACTIVE THREATS DETECTED - DEFENSE PROTOCOLS ENGAGED
              </AlertDescription>
            </Alert>
          )}

          {/* Threat Analysis */}
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400">THREAT ANALYSIS</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-zinc-800 p-4 rounded-lg">
                    <div className="text-2xl font-mono text-cyan-500 mb-1">
                      {battleLogs.filter(log => log.severity === 'warning' || log.severity === 'alert').length}
                    </div>
                    <div className="text-xs font-mono text-zinc-400">ATTACKS DETECTED</div>
                  </div>
                  <div className="bg-zinc-800 p-4 rounded-lg">
                    <div className="text-2xl font-mono text-emerald-500 mb-1">
                      {battleLogs.filter(log => log.severity === 'info').length}
                    </div>
                    <div className="text-xs font-mono text-zinc-400">THREATS NEUTRALIZED</div>
                  </div>
                  <div className="bg-zinc-800 p-4 rounded-lg">
                    <div className="text-2xl font-mono text-red-500 mb-1">
                      {battleLogs.filter(log => log.severity === 'critical').length}
                    </div>
                    <div className="text-xs font-mono text-zinc-400">ACTIVE BREACHES</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Code Viewer */}
          <CodeViewer defenseActions={defenseActions} />
        </div>

        {/* Right Column - Battle Log */}
        <div className="col-span-3">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-500" />
                BATTLE LOG
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 max-h-[800px] overflow-y-auto">
                {battleLogs.map((log, i) => (
                  <div key={i} className="flex items-start gap-2 pb-2 border-b border-zinc-800">
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
                      <div className="text-[10px] font-mono text-zinc-500">
                        {new Date(log.timestamp).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Additional Status Cards */}
          <div className="mt-6">
            <Card className="bg-zinc-900 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono text-zinc-400 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-cyan-500" />
                  DEFENSE STATUS
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
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
          </div>

          {/* Active Connections */}
          <div className="mt-6">
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
                    Last Updated: {new Date().toLocaleTimeString()}
                  </div>
                  <div className="mt-4 space-y-2">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-emerald-500 rounded-full" />
                      <span className="text-xs font-mono text-zinc-300">Main Sensor Array</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-emerald-500 rounded-full" />
                      <span className="text-xs font-mono text-zinc-300">Defense Grid</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-emerald-500 rounded-full" />
                      <span className="text-xs font-mono text-zinc-300">Command Link</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CommandCenter;