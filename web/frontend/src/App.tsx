import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import type { ReactElement } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ThemeProvider, useTheme } from "./context/ThemeContext";
import Layout from "./components/Layout";
import BottomNav from "./components/BottomNav";
import CommandPalette from "./components/CommandPalette";
import { useGlobalShortcuts, ShortcutsHelp } from "./components/Shortcuts";
import OnboardingTour from "./components/OnboardingTour";
import Landing from "./pages/Landing";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import ScanWizard from "./pages/ScanWizard";
import LiveScan from "./pages/LiveScan";
import Findings from "./pages/Findings";
import Kanban from "./pages/Kanban";
import Timeline from "./pages/Timeline";
import SearchPage from "./pages/Search";
import Sla from "./pages/Sla";
import History from "./pages/History";
import Compare from "./pages/Compare";
import Exports from "./pages/Exports";
import Targets from "./pages/Targets";
import Templates from "./pages/Templates";
import Schedules from "./pages/Schedules";
import AuthProfiles from "./pages/AuthProfiles";
import Notifications from "./pages/Notifications";
import ApiKeys from "./pages/ApiKeys";
import AuditLog from "./pages/AuditLog";
import AdminUsers from "./pages/AdminUsers";
import EngineStats from "./pages/EngineStats";
import Profile from "./pages/Profile";
import Settings from "./pages/Settings";
import Overview from "./pages/Overview";

function Guard({ children }: { children: ReactElement }) {
  const { token, ready } = useAuth();
  if (!ready) return <div className="min-h-screen flex items-center justify-center"><div className="shimmer rounded-2xl h-12 w-48" /></div>;
  return token ? children : <Navigate to="/login" replace />;
}

function Shell() {
  const [palette, setPalette] = useState(false);
  const [help, setHelp] = useState(false);
  const { toggle } = useTheme();
  const loc = useLocation();
  useGlobalShortcuts({ onPalette: () => setPalette(true), onHelp: () => setHelp(true) });

  useEffect(() => {
    const h = () => toggle();
    document.addEventListener("sx:theme-toggle", h);
    return () => document.removeEventListener("sx:theme-toggle", h);
  }, [toggle]);

  const showTour = loc.pathname === "/overview" || loc.pathname === "/dashboard";

  return (
    <>
      <Layout onPalette={() => setPalette(true)}>
        <AnimatedRoutes />
      </Layout>
      <BottomNav />
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
      <ShortcutsHelp open={help} onClose={() => setHelp(false)} />
      {showTour && <OnboardingTour />}
    </>
  );
}

function AnimatedRoutes() {
  const loc = useLocation();
  const g = (el: ReactElement) => <Guard>{el}</Guard>;
  return (
    <AnimatePresence mode="wait">
      <Routes location={loc} key={loc.pathname}>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Auth />} />
        <Route path="/overview" element={g(<Overview />)} />
        <Route path="/dashboard" element={g(<Dashboard />)} />
        <Route path="/scan/new" element={g(<ScanWizard />)} />
        <Route path="/scan/:id" element={g(<LiveScan />)} />
        <Route path="/findings/:id" element={g(<Findings />)} />
        <Route path="/findings" element={g(<Findings />)} />
        <Route path="/kanban" element={g(<Kanban />)} />
        <Route path="/timeline" element={g(<Timeline />)} />
        <Route path="/search" element={g(<SearchPage />)} />
        <Route path="/sla" element={g(<Sla />)} />
        <Route path="/history" element={g(<History />)} />
        <Route path="/compare" element={g(<Compare />)} />
        <Route path="/exports" element={g(<Exports />)} />
        <Route path="/targets" element={g(<Targets />)} />
        <Route path="/templates" element={g(<Templates />)} />
        <Route path="/schedules" element={g(<Schedules />)} />
        <Route path="/auth-profiles" element={g(<AuthProfiles />)} />
        <Route path="/notifications" element={g(<Notifications />)} />
        <Route path="/api-keys" element={g(<ApiKeys />)} />
        <Route path="/audit-log" element={g(<AuditLog />)} />
        <Route path="/admin/users" element={g(<AdminUsers />)} />
        <Route path="/engine" element={g(<EngineStats />)} />
        <Route path="/profile" element={g(<Profile />)} />
        <Route path="/settings" element={g(<Settings />)} />
        <Route path="*" element={
          <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
            <div className="text-7xl font-black grad-text">404</div>
            <p className="mt-3 text-slate-500 dark:text-slate-400">This page doesn't exist.</p>
          </div>
        } />
      </Routes>
    </AnimatePresence>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <BrowserRouter>
          <Shell />
        </BrowserRouter>
      </ThemeProvider>
    </AuthProvider>
  );
}
