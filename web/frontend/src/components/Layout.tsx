import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Radar, History, Settings, LogOut, Menu, X, LayoutDashboard, FileWarning, Target, Search, Moon, Sun, User, ChevronDown, Command } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { useState, useRef, useEffect } from "react";

const links = [
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/dashboard", label: "Scan", icon: Radar },
  { to: "/findings", label: "Findings", icon: FileWarning },
  { to: "/targets", label: "Targets", icon: Target },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Layout({ children, onPalette }: { children: React.ReactNode; onPalette: () => void }) {
  const loc = useLocation(); const nav = useNavigate();
  const { user, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const [open, setOpen] = useState(false);
  const [userMenu, setUserMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const h = (e: MouseEvent) => { if (menuRef.current && !menuRef.current.contains(e.target as Node)) setUserMenu(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const isActive = (to: string) => loc.pathname === to || (to !== "/overview" && loc.pathname.startsWith(to + "/"));

  return (
    <div className="min-h-screen">
      <motion.nav
        initial={{ y: -60, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
        className="fixed top-0 inset-x-0 z-50"
      >
        <div className="glass border-x-0 border-t-0">
          <div className="mx-auto flex max-w-7xl items-center gap-2 px-4 sm:px-6 h-16">
            <Link to="/" className="flex items-center gap-2.5 mr-4">
              <motion.div whileHover={{ rotate: 12, scale: 1.1 }} className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 via-violet-500 to-blue-500 shadow-lg shadow-indigo-500/25">
                <Shield className="h-5 w-5 text-white" strokeWidth={2.5} />
              </motion.div>
              <span className="text-lg font-extrabold tracking-tight text-slate-900 dark:text-white">SentinelX</span>
            </Link>
            <div className="hidden lg:flex items-center gap-1">
              {links.map(l => {
                const active = isActive(l.to);
                return (
                  <Link key={l.to} to={l.to} className="relative px-3.5 py-2 rounded-xl text-sm font-medium transition-colors">
                    {active && (
                      <motion.span layoutId="nav-pill" className="absolute inset-0 rounded-xl bg-indigo-50 dark:bg-indigo-500/15 border border-indigo-100 dark:border-indigo-500/20"
                        transition={{ type: "spring", bounce: 0.25, duration: 0.5 }} />
                    )}
                    <span className={`relative flex items-center gap-2 ${active ? "text-indigo-700 dark:text-indigo-300" : "text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"}`}>
                      <l.icon className="h-4 w-4" />{l.label}
                    </span>
                  </Link>
                );
              })}
            </div>
            <div className="flex-1" />
            {user && (
              <button onClick={onPalette}
                className="hidden md:flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm text-slate-400 bg-slate-100/70 dark:bg-white/5 border border-slate-200/60 dark:border-white/10 hover:border-indigo-300 dark:hover:border-indigo-500/30 transition-colors">
                <Search className="h-4 w-4" />
                <span className="text-slate-500 dark:text-slate-400">Search…</span>
                <kbd className="font-mono text-[10px] px-1.5 py-0.5 rounded-md bg-white dark:bg-white/10 border border-slate-200 dark:border-white/10">⌘K</kbd>
              </button>
            )}
            <button onClick={toggle} aria-label="Toggle theme"
              className="p-2.5 rounded-xl text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-white/10 transition-colors">
              {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>
            {user ? (
              <div className="relative" ref={menuRef}>
                <button onClick={() => setUserMenu(!userMenu)}
                  className="hidden sm:flex items-center gap-2 pl-1 pr-2 py-1 rounded-xl hover:bg-slate-100 dark:hover:bg-white/10 transition-colors">
                  <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-violet-500 text-white text-sm font-black">
                    {user.name.charAt(0).toUpperCase()}
                  </span>
                  <ChevronDown className={`h-4 w-4 text-slate-400 transition-transform ${userMenu ? "rotate-180" : ""}`} />
                </button>
                <AnimatePresence>
                  {userMenu && (
                    <motion.div initial={{ opacity: 0, y: 8, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8, scale: 0.97 }}
                      transition={{ duration: 0.15 }}
                      className="absolute right-0 top-12 w-56 glass rounded-2xl p-2 shadow-2xl">
                      <div className="px-3 py-2.5 border-b border-slate-100 dark:border-white/5 mb-1">
                        <div className="text-sm font-bold text-slate-900 dark:text-white truncate">{user.name}</div>
                        <div className="text-xs text-slate-400 truncate font-mono">{user.email}</div>
                      </div>
                      {[
                        { to: "/profile", label: "Profile", icon: User },
                        { to: "/api-keys", label: "API keys", icon: Command },
                        { to: "/settings", label: "Settings", icon: Settings },
                      ].map(l => (
                        <Link key={l.to} to={l.to} onClick={() => setUserMenu(false)}
                          className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-white/10">
                          <l.icon className="h-4 w-4 text-slate-400" />{l.label}
                        </Link>
                      ))}
                      <button onClick={() => { logout(); setUserMenu(false); nav("/"); }}
                        className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-medium text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-500/10">
                        <LogOut className="h-4 w-4" />Logout
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ) : (
              <Link to="/login" className="hidden sm:inline-flex px-5 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 shadow-lg shadow-indigo-600/25 transition-all hover:-translate-y-0.5">
                Get started
              </Link>
            )}
            <button onClick={() => setOpen(!open)} className="lg:hidden p-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-white/10" aria-label="menu">
              {open ? <X className="h-5 w-5 text-slate-600 dark:text-slate-300" /> : <Menu className="h-5 w-5 text-slate-600 dark:text-slate-300" />}
            </button>
          </div>
          <AnimatePresence>
            {open && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                className="lg:hidden overflow-hidden border-t border-slate-100 dark:border-white/5">
                <div className="px-4 py-3 space-y-1 max-h-[70vh] overflow-y-auto">
                  {links.map(l => (
                    <Link key={l.to} to={l.to} onClick={() => setOpen(false)}
                      className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium ${isActive(l.to) ? "bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300" : "text-slate-600 dark:text-slate-300"}`}>
                      <l.icon className="h-4 w-4" />{l.label}
                    </Link>
                  ))}
                  {user && (
                    <button onClick={() => { logout(); setOpen(false); nav("/"); }}
                      className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium text-rose-600 dark:text-rose-400">
                      <LogOut className="h-4 w-4" />Logout
                    </button>
                  )}
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
