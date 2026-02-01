/**
 * StarsBackground - Soothing animated stars/dots background.
 * 
 * Features:
 * - Multiple layers of animated stars/dots
 * - Bright, soothing aesthetic
 * - Smooth, slow animations
 */

export default function StarsBackground() {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
      {/* Stars layer 1 - Large bright dots */}
      <div className="absolute inset-0" style={{
        backgroundImage: `radial-gradient(2px 2px at 20% 30%, rgba(255,255,255,0.8), transparent),
                          radial-gradient(2px 2px at 60% 70%, rgba(255,255,255,0.8), transparent),
                          radial-gradient(1.5px 1.5px at 50% 50%, rgba(255,255,255,0.7), transparent),
                          radial-gradient(1.5px 1.5px at 80% 10%, rgba(255,255,255,0.7), transparent),
                          radial-gradient(2px 2px at 90% 40%, rgba(255,255,255,0.8), transparent),
                          radial-gradient(1px 1px at 33% 60%, rgba(255,255,255,0.6), transparent),
                          radial-gradient(1px 1px at 66% 80%, rgba(255,255,255,0.6), transparent),
                          radial-gradient(2px 2px at 10% 90%, rgba(255,255,255,0.8), transparent),
                          radial-gradient(1.5px 1.5px at 40% 20%, rgba(255,255,255,0.7), transparent),
                          radial-gradient(2px 2px at 70% 50%, rgba(255,255,255,0.8), transparent),
                          radial-gradient(1px 1px at 15% 45%, rgba(255,255,255,0.6), transparent),
                          radial-gradient(1.5px 1.5px at 85% 75%, rgba(255,255,255,0.7), transparent),
                          radial-gradient(1px 1px at 25% 85%, rgba(255,255,255,0.6), transparent),
                          radial-gradient(2px 2px at 75% 15%, rgba(255,255,255,0.8), transparent)`,
        backgroundSize: '200% 200%',
        backgroundPosition: '0% 0%',
        animation: 'starsMove 120s linear infinite',
        opacity: 0.25,
      }} />

      {/* Stars layer 2 - Medium bright dots */}
      <div className="absolute inset-0" style={{
        backgroundImage: `radial-gradient(1px 1px at 25% 25%, rgba(255,255,255,0.5), transparent),
                          radial-gradient(1px 1px at 75% 75%, rgba(255,255,255,0.5), transparent),
                          radial-gradient(1px 1px at 15% 65%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(1px 1px at 85% 35%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(1px 1px at 45% 15%, rgba(255,255,255,0.5), transparent),
                          radial-gradient(1px 1px at 55% 85%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(1px 1px at 35% 45%, rgba(255,255,255,0.5), transparent),
                          radial-gradient(1px 1px at 65% 55%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(1px 1px at 5% 55%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(1px 1px at 95% 25%, rgba(255,255,255,0.5), transparent),
                          radial-gradient(1px 1px at 30% 5%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(1px 1px at 70% 95%, rgba(255,255,255,0.5), transparent)`,
        backgroundSize: '150% 150%',
        backgroundPosition: '0% 0%',
        animation: 'starsMove 100s linear infinite reverse',
        opacity: 0.2,
      }} />

      {/* Stars layer 3 - Small bright dots */}
      <div className="absolute inset-0" style={{
        backgroundImage: `radial-gradient(0.8px 0.8px at 30% 40%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(0.8px 0.8px at 70% 60%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(0.8px 0.8px at 50% 20%, rgba(255,255,255,0.3), transparent),
                          radial-gradient(0.8px 0.8px at 20% 80%, rgba(255,255,255,0.3), transparent),
                          radial-gradient(0.8px 0.8px at 80% 10%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(0.8px 0.8px at 10% 50%, rgba(255,255,255,0.3), transparent),
                          radial-gradient(0.8px 0.8px at 90% 70%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(0.8px 0.8px at 40% 90%, rgba(255,255,255,0.3), transparent),
                          radial-gradient(0.8px 0.8px at 60% 30%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(0.8px 0.8px at 12% 35%, rgba(255,255,255,0.3), transparent),
                          radial-gradient(0.8px 0.8px at 88% 65%, rgba(255,255,255,0.4), transparent),
                          radial-gradient(0.8px 0.8px at 35% 12%, rgba(255,255,255,0.3), transparent),
                          radial-gradient(0.8px 0.8px at 65% 88%, rgba(255,255,255,0.4), transparent)`,
        backgroundSize: '120% 120%',
        backgroundPosition: '0% 0%',
        animation: 'starsMove 140s linear infinite',
        opacity: 0.15,
      }} />

      {/* CSS animation */}
      <style>{`
        @keyframes starsMove {
          0% {
            background-position: 0% 0%;
          }
          100% {
            background-position: 100% 100%;
          }
        }
      `}</style>
    </div>
  );
}
