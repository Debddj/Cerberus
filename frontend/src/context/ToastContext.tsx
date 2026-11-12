import React, { createContext, useCallback, useContext, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, X } from 'lucide-react';

export type ToastVariant = 'success' | 'warning' | 'danger' | 'info';

interface ToastItem {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastContextValue {
  addToast: (toast: Omit<ToastItem, 'id'>) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (toast: Omit<ToastItem, 'id'>) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev.slice(-3), { ...toast, id }]);
      setTimeout(() => removeToast(id), 4500);
    },
    [removeToast]
  );

  const iconFor = (v: ToastVariant) => {
    switch (v) {
      case 'success':
        return <CheckCircle2 className="w-5 h-5 text-[#22B982] shrink-0" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-[#F4AD42] shrink-0" />;
      case 'danger':
        return <ShieldAlert className="w-5 h-5 text-[#F06478] shrink-0" />;
      default:
        return <Info className="w-5 h-5 text-[#6654E8] shrink-0" />;
    }
  };

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      <div className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2.5 max-w-sm w-full pointer-events-none px-4 sm:px-0">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 12, scale: 0.96 }}
              transition={{ duration: 0.18 }}
              className="pointer-events-auto bg-white border border-[#E3DDF8] rounded-2xl p-4 shadow-card flex items-start gap-3"
            >
              {iconFor(t.variant)}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-[#171638]">{t.title}</p>
                {t.description && (
                  <p className="text-xs text-[#666581] mt-0.5 leading-relaxed">{t.description}</p>
                )}
              </div>
              <button
                onClick={() => removeToast(t.id)}
                className="text-[#666581] hover:text-[#171638] p-0.5 rounded-lg"
                aria-label="Dismiss notification"
              >
                <X className="w-4 h-4" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
};

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

