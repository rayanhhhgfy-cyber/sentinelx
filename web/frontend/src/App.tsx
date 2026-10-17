import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import type { ReactElement } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Layout from "./components/Layout";
import Landing from "./pages/Landing";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import LiveScan from "./pages/LiveScan";
import Findings from "./pages/Findings";
import History from "./pages/History";
import Settings from "./pages/Settings";
import Overview from "./pages/Overview";

function Guard({ children }: { children: ReactElement }) {
  const { token, ready } = useAuth();
  if (!ready) return <div className="min-h-screen flex items-center justify-center"><div className="shimmer rounded-2xl h-12 w-48" /></div>;
  return token ? children : <Navigate to="/login" replace />;
}

function AnimatedRoutes() {
  const loc = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={loc} key={loc.pathname}>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Auth />} />
        <Route path="/overview" element={<Guard><Overview /></Guard>} />
        <Route path="/dashboard" element={<Guard><Dashboard /></Guard>} />
        <Route path="/scan/:id" element={<Guard><LiveScan /></Guard>} />
        <Route path="/findings/:id" element={<Guard><Findings /></Guard>} />
        <Route path="/findings" element={<Guard><Findings /></Guard>} />
        <Route path="/history" element={<Guard><History /></Guard>} />
        <Route path="/settings" element={<Guard><Settings /></Guard>} />
        <Route path="*" element={
          <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
            <div className="text-7xl font-black grad-text">404</div>
            <p className="mt-3 text-slate-500">This page doesn't exist.</p>
          </div>
        } />
      </Routes>
    </AnimatePresence>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Layout><AnimatedRoutes /></Layout>
      </BrowserRouter>
    </AuthProvider>
  );
}
