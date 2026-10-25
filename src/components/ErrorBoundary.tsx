import { Component, type ErrorInfo, type ReactNode } from "react";

import { t } from "../i18n";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  override componentDidCatch(error: Error, _info: ErrorInfo) {
    console.error("[MineBurp] view crashed:", error);
  }

  override render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div className="error-boundary" role="alert">
          <h3>{t("error.boundary.title")}</h3>
          <p>{this.state.error?.message ?? t("error.boundary.unknown")}</p>
          <button
            type="button"
            className="button"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            {t("error.boundary.retry")}
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
