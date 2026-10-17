import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";

type Theme = "light" | "dark";
interface ThemeCtx { theme: Theme; toggle: () => void; set: (t: Theme) => void; }
const Ctx = createContext<ThemeCtx>(null!);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const s = localStorage.getItem("sx_theme");
    if (s === "dark" || s === "light") return s;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("sx_theme", theme);
  }, [theme]);
  const toggle = () => setTheme(t => (t === "dark" ? "light" : "dark"));
  const set = (t: Theme) => setTheme(t);
  return <Ctx.Provider value={{ theme, toggle, set }}>{children}</Ctx.Provider>;
}
export const useTheme = () => useContext(Ctx);
