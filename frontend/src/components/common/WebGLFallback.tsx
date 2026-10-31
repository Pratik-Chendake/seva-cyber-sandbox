import React from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

interface WebGLFallbackProps {
  title?: string;
  description?: string;
  onRetry?: () => void;
}

export const WebGLFallback: React.FC<WebGLFallbackProps> = ({
  title = 'Interactive 2D Visualization Active',
  description = 'WebGL hardware acceleration is paused or running in compatibility mode. A lightweight interactive 2D model is rendered.',
  onRetry,
}) => {
  return (
    <div className="w-full h-full min-h-[300px] flex flex-col items-center justify-center p-8 text-center rounded-2xl liquid-glass border border-[#DDDCD3]">
      <div className="w-12 h-12 rounded-2xl bg-[#DFE9E1] flex items-center justify-center text-[#477C78] mb-3">
        <ShieldAlert className="w-6 h-6" />
      </div>
      <h4 className="text-sm font-semibold text-[#202C32] mb-1">{title}</h4>
      <p className="text-xs text-[#738087] max-w-md mb-4">{description}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-3 py-1.5 rounded-lg liquid-glass text-xs text-[#202C32] hover:bg-white flex items-center gap-1.5 cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Reload Accelerated Canvas</span>
        </button>
      )}
    </div>
  );
};
