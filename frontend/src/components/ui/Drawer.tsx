import React, { useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}

export const Drawer: React.FC<DrawerProps> = ({ open, onClose, title, subtitle, children }) => {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-[#171638]/30 backdrop-blur-[2px]"
          />
          <motion.aside
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 28, stiffness: 280 }}
            className="relative z-10 w-full max-w-2xl bg-white border-l border-[#E3DDF8] h-full overflow-y-auto shadow-2xl flex flex-col"
          >
            <div className="sticky top-0 z-10 bg-white/95 backdrop-blur border-b border-[#E3DDF8] px-6 py-4 flex items-center justify-between">
              <div className="min-w-0 pr-4">
                <h3 className="text-lg font-bold text-[#171638] truncate">{title}</h3>
                {subtitle && <p className="text-xs font-mono text-[#666581] mt-0.5 truncate">{subtitle}</p>}
              </div>
              <button
                onClick={onClose}
                className="p-2 rounded-xl bg-[#F3F0FF] hover:bg-[#EAE6FF] text-[#666581] hover:text-[#171638] transition-colors"
                aria-label="Close drawer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 flex-1">{children}</div>
          </motion.aside>
        </div>
      )}
    </AnimatePresence>
  );
};

