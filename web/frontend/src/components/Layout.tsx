import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Home, Radar, History, Settings, LogOut, Menu, X, Sparkles, LayoutDashboard } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useState } from "react";

const links = [
  { to: "/", label: "Home", icon: Home },
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/dashboard", label: "Scan", icon: Radar },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const loc = useLocation(); const nav = useNavigate();
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);

  return (
    <div className="min-h-screen">
      <motion.nav
        initial={{ y: -60, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
        className="fixed top-0 inset-x-0 z-50"
      >
        <div className="glass border-x-0 border-t-0">
          <div className="mx-auto flex max-w-7xl items-center gap-2 px-4 sm:px-6 h-16">
            <Link to="/" className="flex items-center gap-2.5 mr-6">
              <motion.div whileHover={{ rotate: 12, scale: 1.1 }} className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 via-violet-500 to-blue-500 shadow-lg shadow-indigo-500/25">
                <Shield className="h-5 w-5 text-white" strokeWidth={2.5} />
              </motion.div>
              <span className="text-lg font-extrabold tracking-tight text-slate-900">SentinelX</span>
            </Link>
            <div className="hidden md:flex items-center gap-1">
              {links.map(l => {
                const active = loc.pathname === l.to;
                return (
                  <Link key={l.to} to={l.to} className="relative px-4 py-2 rounded-xl text-sm font-medium transition-colors">
                    {active && (
                      <motion.span layoutId="nav-pill" className="absolute inset-0 rounded-xl bg-indigo-50 border border-indigo-100"
                        transition={{ type: "spring", bounce: 0.25, duration: 0.5 }} />
                    )}
                    <span className={`relative flex items-center gap-2 ${active ? "text-indigo-700" : "text-slate-500 hover:text-slate-900"}`}>
                      <l.icon className="h-4 w-4" />{l.label}
                    </span>
                  </Link>
                );
              })}
            </div>
            <div className="flex-1" />
            {user ? (
              <div className="hidden sm:flex items-center gap-3">
                <span className="flex items-center gap-1.5 text-sm text-slate-500">
                  <Sparkles className="h-4 w-4 text-amber-500" />{user.name}
                </span>
                <button onClick={() => { logout(); nav("/"); }}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium text-slate-600 hover:bg-slate-100 transition-colors">
                  <LogOut className="h-4 w-4" />Logout
                </button>
              </div>
            ) : (
              <Link to="/login" className="hidden sm:inline-flex px-5 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 shadow-lg shadow-indigo-600/25 transition-all hover:-translate-y-0.5">
                Get started
              </Link>
            )}
            <button onClick={() => setOpen(!open)} className="md:hidden p-2.5 rounded-xl hover:bg-slate-100" aria-label="menu">
              {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
          <AnimatePresence>
            {open && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                className="md:hidden overflow-hidden border-t border-slate-100">
                <div className="px-4 py-3 space-y-1">
                  {links.map(l => (
                    <Link key={l.to} to={l.to} onClick={() => setOpen(false)}
                      className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium ${loc.pathname === l.to ? "bg-indigo-50 text-indigo-700" : "text-slate-600"}`}>
                      <l.icon className="h-4 w-4" />{l.label}
                    </Link>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.nav>
      <main className="pt-16">{children}</main>
    </div>
  );
}
