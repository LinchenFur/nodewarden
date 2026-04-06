import { Component, type ComponentChildren } from 'preact';
import { AlertTriangle, RefreshCw } from 'lucide-preact';
import { t } from '@/lib/i18n';

interface RouteErrorBoundaryProps {
  children: ComponentChildren;
  resetKey?: string;
  title?: string;
  description?: string;
}

interface RouteErrorBoundaryState {
  error: Error | null;
  componentStack: string;
}

export default class RouteErrorBoundary extends Component<
  RouteErrorBoundaryProps,
  RouteErrorBoundaryState
> {
  state: RouteErrorBoundaryState = {
    error: null,
    componentStack: '',
  };

  componentDidCatch(error: Error, errorInfo: { componentStack?: string }) {
    this.setState({
      error,
      componentStack: String(errorInfo?.componentStack || ''),
    });
  }

  componentDidUpdate(prevProps: RouteErrorBoundaryProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({
        error: null,
        componentStack: '',
      });
    }
  }

  private handleRetry = () => {
    this.setState({
      error: null,
      componentStack: '',
    });
  };

  render() {
    if (!this.state.error) {
      return this.props.children;
    }

    const stack = (this.state.error.stack || this.state.componentStack || '').trim();
    const preview = stack
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 6)
      .join('\n');

    return (
      <section className="card route-error-card">
        <div className="route-error-head">
          <AlertTriangle size={18} />
          <strong>{this.props.title || t('txt_page_runtime_error')}</strong>
        </div>
        <p className="route-error-copy">
          {this.props.description || t('txt_page_runtime_error_help')}
        </p>
        <div className="route-error-block">
          <div className="route-error-label">{t('txt_error_message')}</div>
          <pre className="route-error-pre">{this.state.error.message || String(this.state.error)}</pre>
        </div>
        {!!preview && (
          <div className="route-error-block">
            <div className="route-error-label">{t('txt_error_stack_preview')}</div>
            <pre className="route-error-pre">{preview}</pre>
          </div>
        )}
        <div className="actions">
          <button type="button" className="btn btn-secondary" onClick={this.handleRetry}>
            <RefreshCw size={14} className="btn-icon" />
            {t('txt_retry')}
          </button>
        </div>
      </section>
    );
  }
}
