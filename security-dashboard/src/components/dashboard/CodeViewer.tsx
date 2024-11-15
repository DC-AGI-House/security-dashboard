import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Terminal, Shield, XSquare } from 'lucide-react';

// Types
interface DefenseAction {
  id: string;
  timestamp: string;
  code: string;
  status: 'active' | 'pending' | 'completed';
  description: string;
}

interface CodeViewerProps {
  defenseActions: DefenseAction[];
}

const CodeViewer: React.FC<CodeViewerProps> = ({ defenseActions }) => {
  const [currentCode, setCurrentCode] = useState<string>('');
  const [isTyping, setIsTyping] = useState(false);
  const [liveDefense, setLiveDefense] = useState<DefenseAction[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  // Typing animation effect
  useEffect(() => {
    if (liveDefense.length > 0 && !isTyping) {
      const latestAction = liveDefense[0];
      setIsTyping(true);
      let index = 0;
      
      const typeCode = () => {
        if (index < latestAction.code.length) {
          setCurrentCode(prev => prev + latestAction.code.charAt(index));
          index++;
          setTimeout(typeCode, Math.random() * 30 + 20); // Random typing speed
        } else {
          setIsTyping(false);
        }
      };
      
      setCurrentCode('');
      typeCode();
    }
  }, [liveDefense]);

  // WebSocket connection
  useEffect(() => {
    const connectWebSocket = () => {
      const ws = new WebSocket('ws://localhost:8000/ws/defense');
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('Defense WebSocket Connected');
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'defense_update') {
          setLiveDefense(prev => [data.action, ...prev].slice(0, 5));
        }
      };

      ws.onclose = () => {
        console.log('Defense WebSocket Disconnected');
        setTimeout(connectWebSocket, 5000);
      };
    };

    connectWebSocket();

    // Cleanup
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Generate dummy updates for demonstration
  useEffect(() => {
    const dummyUpdates = [
      {
        id: '1',
        description: 'Generating firewall rules to block detected attack vector',
        code: `iptables -A INPUT -s ${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)} -j DROP
iptables -A OUTPUT -d malicious-domain.com -j DROP
systemctl restart firewalld`,
        status: 'active',
      },
      {
        id: '2',
        description: 'Deploying rate limiting for suspicious IP range',
        code: `limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
limit_req zone=mylimit burst=20 nodelay;
deny all;`,
        status: 'active',
      },
      {
        id: '3',
        description: 'Implementing additional authentication checks',
        code: `@require_authentication
def secure_endpoint():
    if not verify_2fa(current_user):
        raise SecurityException("2FA Required")
    if is_suspicious_ip(request.remote_addr):
        raise SecurityException("IP Blocked")
    return proceed()`,
        status: 'active',
      }
    ];

    // Simulate incoming updates
    const interval = setInterval(() => {
      const randomUpdate = dummyUpdates[Math.floor(Math.random() * dummyUpdates.length)];
      const newAction = {
        ...randomUpdate,
        id: Date.now().toString(),
        timestamp: new Date().toISOString(),
      };
      setLiveDefense(prev => [newAction, ...prev].slice(0, 5));
    }, 10000);

    return () => clearInterval(interval);
  }, []);

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
                  DEFENSE CODE OUTPUT
                </span>
              </div>
            </div>
            <pre className="bg-black rounded p-2 overflow-x-auto min-h-[200px]">
              <code className="text-xs font-mono text-cyan-500">
                {currentCode || '// Awaiting new defense generation...'}
              </code>
            </pre>
          </div>

          <div className="space-y-2">
            <div className="text-xs font-mono text-zinc-400 mb-2">RECENT DEFENSES</div>
            {liveDefense.slice(1).map((action) => (
              <div
                key={action.id}
                className="bg-black/30 rounded-lg p-3 border border-zinc-800/50"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-zinc-300">
                    {action.description}
                  </span>
                  <span className="text-[10px] font-mono text-zinc-500">
                    {new Date(action.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default CodeViewer;