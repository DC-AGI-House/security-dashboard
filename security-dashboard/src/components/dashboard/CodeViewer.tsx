import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Terminal, Shield } from 'lucide-react';

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

const CodeViewer: React.FC = () => {
  const [currentCode, setCurrentCode] = useState<string>('');
  const [isTyping, setIsTyping] = useState(false);
  const [allCode, setAllCode] = useState<string[]>([]);
  const typeTimeoutRef = useRef<NodeJS.Timeout>();

  useEffect(() => {
    // Start typing animation immediately
    animateNewCode(SAMPLE_CODE);
    
    return () => {
      if (typeTimeoutRef.current) {
        clearTimeout(typeTimeoutRef.current);
      }
    };
  }, []);

  // Typing animation for new code
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

export default CodeViewer;