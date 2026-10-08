import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from './authState';

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, restoring } = useAuth();
  if (restoring) return null; // don't bounce to /login before a reload's session check finishes
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}
