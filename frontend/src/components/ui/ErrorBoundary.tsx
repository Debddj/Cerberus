import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from './Button';

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  state: State = { hasError: false, message: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error.message || 'Unexpected rendering error' };
  }

  componentDidCatch(error: Error) {
    console.error('CERBERUS UI ErrorBoundary caught error:', error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[60vh] flex items-center justify-center p-6">
          <div className="cerberus-card p-8 max-w-md w-full text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-[#F06478]/12 text-[#F06478] flex items-center justify-center mx-auto">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-[#171638]">Interface Error Recovered</h3>
            <p className="text-sm text-[#666581]">{this.state.message}</p>
            <Button onClick={() => this.setState({ hasError: false, message: '' })}>
              <RefreshCw className="w-4 h-4" />
              Reload View
            </Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

