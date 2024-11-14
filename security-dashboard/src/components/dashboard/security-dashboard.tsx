'use client'

import React, { useState, useEffect } from 'react';
import { Shield, Cpu, Activity, AlertTriangle, TrendingUp, Radio, Target, CrosshairIcon, ShieldAlert, Terminal, Network, ChevronRight, Wifi, Box } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from "@/components/ui/progress";

// Types for backend integration
interface SystemStatus {
  name: string;
  status: 'operational' | 'compromised' | 'offline';
  load: number;
  lastHeartbeat: string;
  ipAddress: string;
  services: ServiceStatus[];
}

interface ServiceStatus {
  name: string;
  status: 'running' | 'stopped' | 'error';
  uptime: number;
}

interface Threat {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  target: string;
  timestamp: string;
  status: 'active' | 'mitigated' | 'investigating';
}

interface DefenseMetrics {
  attacksDetected: number;
  attacksBlocked: number;
  vulnerabilitiesFound: number;
  patchesDeployed: number;
  averageResponseTime: number;
}

const CommandCenter = () => {
  // State management for real-time data
  const [systems, setSystems] = useState<{[key: string]: SystemStatus}>({});
  const [activeThreats, setActiveThreats] = useState<Threat[]>([]);
  const [metrics, setMetrics] = useState<DefenseMetrics>({
    attacksDetected: 0,
    attacksBlocked: 0,
    vulnerabilitiesFound: 0,
    patchesDeployed: 0,
    averageResponseTime: 0
  });

  // Simulate WebSocket connection for demo purposes
  useEffect(() => {
    // Simulate real-time updates
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        attacksDetected: prev.attacksDetected + Math.floor(Math.random() * 2),
        attacksBlocked: prev.attacksBlocked + Math.floor(Math.random() * 2),
        vulnerabilitiesFound: Math.min(3, Math.floor(Math.random() * 5))
      }));
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      {/* Top Bar */}
      <div className="flex justify-between items-center mb-8 border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-4">
          <div className="h-10 w-1 bg-cyan-500" /> {/* Accent bar */}
          <div>
            <h1 className="text-3xl font-mono tracking-tight text-zinc-100">CYBER COMMAND</h1>
            <div className="flex items-center gap-2 mt-1">
              <div className="h-2 w-2 bg-cyan-500 rounded-full animate-pulse" />
              <p className="text-xs font-mono text-zinc-400 tracking-widest">OPERATIONAL STATUS: ACTIVE</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex flex-col items-end">
            <div className="text-xs font-mono text-zinc-400">SYSTEM TIME</div>
            <div className="text-sm font-mono text-cyan-500">{new Date().toLocaleTimeString()}</div>
          </div>
          <div className="flex gap-2">
            <Wifi className="h-5 w-5 text-cyan-500" />
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
              {/* Individual System Status */}
              <div className="space-y-4">
                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">TARGET SYSTEM</span>
                    <span className="text-xs font-mono text-cyan-500">ONLINE</span>
                  </div>
                  <Progress value={75} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">METASPLOITABLE 3 / GTX 1650</div>
                </div>

                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">DEFENSE GRID</span>
                    <span className="text-xs font-mono text-cyan-500">ACTIVE</span>
                  </div>
                  <Progress value={90} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">M1 MAX / OLLAMA CORE</div>
                </div>

                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">IDS NETWORK</span>
                    <span className="text-xs font-mono text-cyan-500">SCANNING</span>
                  </div>
                  <Progress value={85} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">SNORT / ML MONITORING</div>
                </div>

                <div className="relative">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-mono text-zinc-300">ADVERSARY</span>
                    <span className="text-xs font-mono text-red-500">DETECTED</span>
                  </div>
                  <Progress value={95} className="h-1" />
                  <div className="text-[10px] font-mono text-zinc-500 mt-1">KALI / NAT ENABLED</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Center Column - Main Display */}
        <div className="col-span-6 space-y-6">
          {/* Threat Alert */}
          {metrics.vulnerabilitiesFound > 0 && (
            <Alert className="bg-red-950/30 border-red-900/50 text-red-200">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <AlertDescription className="text-xs font-mono ml-2">
                CRITICAL: {metrics.vulnerabilitiesFound} ACTIVE THREATS - DEFENSE PROTOCOLS ENGAGED
              </AlertDescription>
            </Alert>
          )}

          {/* Main Display Card */}
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono text-zinc-400">THREAT ANALYSIS</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-zinc-800 p-4 rounded-lg">
                    <div className="text-2xl font-mono text-cyan-500 mb-1">{metrics.attacksDetected}</div>
                    <div className="text-xs font-mono text-zinc-400">ATTACKS DETECTED</div>
                  </div>
                  <div className="bg-zinc-800 p-4 rounded-lg">
                    <div className="text-2xl font-mono text-emerald-500 mb-1">{metrics.attacksBlocked}</div>
                    <div className="text-xs font-mono text-zinc-400">THREATS NEUTRALIZED</div>
                  </div>
                  <div className="bg-zinc-800 p-4 rounded-lg">
                    <div className="text-2xl font-mono text-red-500 mb-1">{metrics.vulnerabilitiesFound}</div>
                    <div className="text-xs font-mono text-zinc-400">ACTIVE BREACHES</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
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
              <div className="space-y-3 max-h-[400px] overflow-y-auto">
                {[...Array(10)].map((_, i) => (
                  <div key={i} className="flex items-start gap-2 pb-2 border-b border-zinc-800">
                    <ChevronRight className="h-4 w-4 text-cyan-500 mt-1" />
                    <div>
                      <div className="text-xs font-mono text-zinc-300">
                        {i === 0 ? "SQL Injection Attempt Detected" :
                         i === 1 ? "Port Scan Blocked" :
                         "System Status Update"}
                      </div>
                      <div className="text-[10px] font-mono text-zinc-500">
                        {i === 0 ? "2 min ago" :
                         i === 1 ? "5 min ago" :
                         `${i * 5 + 10} min ago`}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default CommandCenter;