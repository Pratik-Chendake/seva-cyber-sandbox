import React from 'react';
import { Shield, Loader2 } from 'lucide-react';

interface ThreeLoadingFallbackProps {
  label?: string;
  className?: string;
}

export const ThreeLoadingFallback: React.FC<ThreeLoadingFallbackProps> = ({
  label = 'Initializing 3D Material...',
  className = 'w-full h-full min-h-[360px]',
}) => {
  return (
    <div
      className={`liquid-glass rounded-2xl flex flex-col items-center justify-center p-6 border border-soft-stone/40 animate-pulse ${className}`}
    >
      <div className="relative mb-3 flex items-center justify-center">
        <div className="w-12 h-12 rounded-xl bg-mineral-teal/10 flex items-center justify-center text-mineral-teal">
          <Shield className="w-6 h-6 stroke-[1.8]" />
        </div>
        <Loader2 className="w-14 h-14 text-mineral-teal/40 animate-spin absolute" />
      </div>
      <span className="text-xs font-mono text-slate-grey tracking-wide uppercase">
        {label}
      </span>
      <span className="text-[10px] text-slate-grey/70 mt-1">
        Local WebGL Shaders &bull; 0 KB Cloud Data
      </span>
    </div>
  );
};
