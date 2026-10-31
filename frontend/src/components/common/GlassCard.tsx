import React from 'react';

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  elevated?: boolean;
  interactive?: boolean;
  onClick?: () => void;
}

export const GlassCard: React.FC<GlassCardProps> = ({
  children,
  className = '',
  elevated = false,
  interactive = false,
  onClick,
}) => {
  const baseClass = elevated
    ? 'liquid-glass-elevated'
    : interactive
    ? 'liquid-glass-card cursor-pointer'
    : 'liquid-glass';

  return (
    <div
      onClick={onClick}
      className={`rounded-2xl p-6 transition-all duration-300 relative overflow-hidden ${baseClass} ${className}`}
    >
      {/* Specular Edge Gradient Highlight */}
      <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-white/80 to-transparent pointer-events-none" />

      {/* Content */}
      <div className="relative z-10">{children}</div>
    </div>
  );
};
