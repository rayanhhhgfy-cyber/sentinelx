import { createContext, useContext, useState, useEffect } from "react";
import type { ReactNode } from "react";
import { api } from "../lib/api";
import type { User } from "../lib/api";

interface AuthCtx {
  user: User|null; token: string|null;
  login:(e:string,p:string)=>Promise<void>;
  register:(e:string,n:string,p:string)=>Promise<void>;
  logout:()=>void; ready: boolean;
}
const Ctx = createContext<AuthCtx>(null!);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string|null>(() => localStorage.getItem("sx_token"));
  const [user, setUser] = useState<User|null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (token) api.me().then(setUser).catch(() => { localStorage.removeItem("sx_token"); setToken(null); }).finally(()=>setReady(true));
    else setReady(true);
  }, [token]);
  const login = async (email:string,password:string) => {
    const r = await api.login(email,password);
    localStorage.setItem("sx_token", r.token); setToken(r.token); setUser(r.user);
  };
  const register = async (email:string,name:string,password:string) => {
    const r = await api.register(email,name,password);
    localStorage.setItem("sx_token", r.token); setToken(r.token); setUser(r.user);
  };
  const logout = () => { api.logout().catch(()=>{}); localStorage.removeItem("sx_token"); setToken(null); setUser(null); };
  return <Ctx.Provider value={{user,token,login,register,logout,ready}}>{children}</Ctx.Provider>;
}
export const useAuth = () => useContext(Ctx);
