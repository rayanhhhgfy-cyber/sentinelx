import { Link, useLocation } from "react-router-dom";
import { LayoutDashboard, Radar, FileWarning, History, User } from "lucide-react";
import { useAuth } from "../context/AuthContext";

const links = [
  { to: "/overview", label: "Home", icon: LayoutDashboard },
  { to: "/dashboard", label: "Scan", icon: Radar },
  { to: "/findings", label: "Findings", icon: FileWarning },
  { to: "/history", label: "History", icon: History },
  { to: "/profile", label: "Profile", icon: User },
];

export default function BottomNav() {
  const loc = useLocation();
  const { token } = useAuth();
  if (!token) return null;
  return (
    <nav className="md:hidden fixed bottom-0 inset-x-0 z-50 pb-[env(safe-area-inset-bottom)]">
      <div className="glass border-x-0 border-b-0 mx-3 mb-3 rounded-3xl">
        <div className="grid grid-cols-5 px-2 py-2">
          {links.map(l => {
            const active = loc.pathname === l.to || (l.to !== "/overview" && loc.pathname.startsWith(l.to + "/"));
            return (
              <Link key={l.to} to={l.to}
                className={`flex flex-col items-center gap-1 py-2 rounded-2xl text-[10px] font-bold transition-colors ${active ? "text-indigo-600 dark:text-indigo-400" : "text-slate-400 dark:text-slate-500"}`}>
                <span className={`p-1.5 rounded-xl ${active ? "bg-indigo-50 dark:bg-indigo-500/15" : ""}`}>
                  <l.icon className="h-5 w-5" />
                </span>
                {l.label}
              </Link>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
