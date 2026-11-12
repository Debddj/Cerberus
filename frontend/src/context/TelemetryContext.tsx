import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { fetchEvents, fetchHealth, fetchMetrics, subscribeToEventStream } from '../services/api';
import type { HealthStatus, MetricsSummary, ToolCallEvent } from '../types';

interface TelemetryContextValue {
  metrics: MetricsSummary | null;
  health: HealthStatus | null;
  events: ToolCallEvent[];
  connectionSource: 'live' | 'offline-demo';
  isStreaming: boolean;
  loading: boolean;
  lastUpdated: Date | null;
  refreshAll: () => Promise<void>;
  prependEvent: (ev: ToolCallEvent) => void;
}

const TelemetryContext = createContext<TelemetryContextValue | undefined>(undefined);

export const TelemetryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [events, setEvents] = useState<ToolCallEvent[]>([]);
  const [connectionSource, setConnectionSource] = useState<'live' | 'offline-demo'>('live');
  const [isStreaming, setIsStreaming] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    try {
      const [mRes, hRes, eRes] = await Promise.all([
        fetchMetrics(),
        fetchHealth(),
        fetchEvents(150),
      ]);
      setMetrics(mRes.data);
      setHealth(hRes.data);
      setEvents(eRes.data);
      setConnectionSource(
        mRes.source === 'live' && hRes.source === 'live' ? 'live' : 'offline-demo'
      );
      setLastUpdated(new Date());
    } finally {
      setLoading(false);
    }
  }, []);

  const prependEvent = useCallback((ev: ToolCallEvent) => {
    setEvents((prev) => {
      if (prev.some((existing) => existing.event_id === ev.event_id)) return prev;
      return [ev, ...prev].slice(0, 250);
    });
  }, []);

  useEffect(() => {
    refreshAll();
    const unsub = subscribeToEventStream(
      (newEvent) => {
        setConnectionSource('live');
        prependEvent(newEvent);
      },
      (connected) => setIsStreaming(connected)
    );

    const interval = setInterval(() => {
      fetchMetrics().then((res) => {
        setMetrics(res.data);
        setConnectionSource(res.source);
      });
      fetchHealth().then((res) => setHealth(res.data));
    }, 10000);

    return () => {
      unsub();
      clearInterval(interval);
    };
  }, [refreshAll, prependEvent]);

  return (
    <TelemetryContext.Provider
      value={{
        metrics,
        health,
        events,
        connectionSource,
        isStreaming,
        loading,
        lastUpdated,
        refreshAll,
        prependEvent,
      }}
    >
      {children}
    </TelemetryContext.Provider>
  );
};

export function useTelemetry(): TelemetryContextValue {
  const ctx = useContext(TelemetryContext);
  if (!ctx) throw new Error('useTelemetry must be used within TelemetryProvider');
  return ctx;
}

