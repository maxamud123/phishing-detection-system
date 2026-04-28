import { Component, ReactNode } from 'react';

interface Props  { children: ReactNode; }
interface State  { hasError: boolean; message: string; }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, message: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error.message };
  }

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center px-6">
          <p style={{ fontSize: '15px', fontWeight: 700, color: '#ef4444', marginBottom: '8px' }}>
            Something went wrong
          </p>
          <p style={{ fontSize: '13px', color: '#8B4555', marginBottom: '16px' }}>
            {this.state.message || 'An unexpected error occurred in this section.'}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, message: '' })}
            className="px-4 py-2 rounded-lg text-sm font-semibold transition-all"
            style={{ background: 'rgba(240, 192, 200,0.1)', border: '1px solid rgba(240, 192, 200,0.3)', color: '#F0C0C8' }}>
            Try Again
          </button>
        </div>
      </div>
    );
  }
}
