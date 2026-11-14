import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { EventStreamView } from './components/EventStreamView';
import { AttackChainView } from './components/AttackChainView';
import { PolicyManagerView } from './components/PolicyManagerView';
import { BaselineView } from './components/BaselineView';
import { AuditLedgerView } from './components/AuditLedgerView';
import { TelemetryView } from './components/TelemetryView';
import { ChallengeInboxView } from './components/ChallengeInboxView';
import { AttackReplayTheater } from './components/AttackReplayTheater';
import { SecurityMatrixView } from './components/SecurityMatrixView';
import { AgentIdentityView } from './components/AgentIdentityView';
import { ToolCallEvent, MetricsSummary, HealthStatus } from './types';
import { fetchMetrics, fetchHealth, fetchEvents, fetchChallenges, subscribeToEventStream } from './api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('events');
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [events, setEvents] = useState<ToolCallEvent[]>([]);
  const [pendingChallengesCount, setPendingChallengesCount] = useState<number>(0);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);

  const loadInitialData = useCallback(async () => {
    setLoading(true);
    try {
      const [m, h, evs, chs] = await Promise.all([
        fetchMetrics().catch(() => null),
        fetchHealth().catch(() => null),
        fetchEvents(100).catch(() => []),
        fetchChallenges().catch(() => []),
      ]);
      if (m) setMetrics(m);
      if (h) setHealth(h);
      if (evs) setEvents(evs);
      if (chs) {
        setPendingChallengesCount(chs.filter((c) => c.status === 'pending').length);
      }
    } catch (err) {
      console.error('Error loading Cerberus SOC telemetry:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadInitialData();

    // Subscribe to live SSE events
    const unsubscribe = subscribeToEventStream((newEvent) => {
      setIsStreaming(true);
      setEvents((prev) => {
        // Deduplicate
        if (prev.some((e) => e.event_id === newEvent.event_id)) {
          return prev;
        }
        return [newEvent, ...prev].slice(0, 200);
      });
      if (newEvent.decision === 'challenge') {
        setPendingChallengesCount((prev) => prev + 1);
      }
    });

    // Refresh telemetry every 10 seconds
    const interval = setInterval(() => {
      fetchMetrics().then(setMetrics).catch(() => {});
      fetchHealth().then(setHealth).catch(() => {});
      fetchChallenges()
        .then((chs) => setPendingChallengesCount(chs.filter((c) => c.status === 'pending').length))
        .catch(() => {});
    }, 10000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, [loadInitialData]);

  return (
    <div className="min-h-screen bg-soc-bg text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar
        metrics={metrics}
        health={health}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isStreaming={isStreaming}
        onRefresh={loadInitialData}
        loading={loading}
        pendingChallengesCount={pendingChallengesCount}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'events' && (
          <EventStreamView events={events} isStreaming={isStreaming} />
        )}
        {activeTab === 'challenges' && (
          <ChallengeInboxView />
        )}
        {activeTab === 'timeline' && (
          <AttackChainView events={events} />
        )}
        {activeTab === 'theater' && (
          <AttackReplayTheater />
        )}
        {activeTab === 'scanners' && (
          <SecurityMatrixView />
        )}
        {activeTab === 'identity' && (
          <AgentIdentityView />
        )}
        {activeTab === 'policies' && (
          <PolicyManagerView />
        )}
        {activeTab === 'baselines' && (
          <BaselineView />
        )}
        {activeTab === 'audit' && (
          <AuditLedgerView />
        )}
        {activeTab === 'telemetry' && (
          <TelemetryView metrics={metrics} health={health} events={events} />
        )}
      </main>

      <footer className="border-t border-soc-border py-4 text-center text-xs font-mono text-slate-500">
        Cerberus MCP Behavioral Firewall • Zero-Trust Runtime Protection for Autonomous Agents
      </footer>
    </div>
  );
};
