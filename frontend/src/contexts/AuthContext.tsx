import React, { createContext, useContext, useEffect, useState } from 'react'
import { createClient, User, Session } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY

const isSupabaseConfigured = supabaseUrl && supabaseAnonKey && 
  supabaseUrl !== 'your_supabase_project_url_here' && 
  supabaseAnonKey !== 'your_supabase_anon_key_here'

export const supabase = isSupabaseConfigured 
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null

interface UserPermissions {
  role: string
  features: Record<string, boolean>
  canBypassMFA: boolean
  canExtendSession: boolean
  hasUnlimitedTokens: boolean
  maxSessionHours: number
}

interface AuthContextType {
  user: User | null
  session: Session | null
  userPermissions: UserPermissions | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<{ error?: any }>
  signUp: (email: string, password: string) => Promise<{ error?: any }>
  signOut: () => Promise<{ success: boolean; error?: any }>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

const DEMO_USER_KEY = 'cobra-demo-user'

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [userPermissions, setUserPermissions] = useState<UserPermissions | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!supabase) {
      // Demo mode
      const storedDemoUser = localStorage.getItem(DEMO_USER_KEY)
      if (storedDemoUser) {
        try {
          const demoUser = JSON.parse(storedDemoUser)
          setUser(demoUser)
        } catch (error) {
          localStorage.removeItem(DEMO_USER_KEY)
        }
      }
      setLoading(false)
      return
    }

    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
      setUser(session?.user ?? null)
      setLoading(false)
    })

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
      setSession(session)
      setUser(session?.user ?? null)
      setLoading(false)
    })

    return () => subscription.unsubscribe()
  }, [])

  const signIn = async (email: string, password: string) => {
    if (!supabase) {
      // Demo mode
      const demoUser = { id: 'demo-user', email } as User
      setUser(demoUser)
      localStorage.setItem(DEMO_USER_KEY, JSON.stringify(demoUser))
      return { error: null }
    }
    
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })
    
    return { error }
  }

  const signUp = async (email: string, password: string) => {
    if (!supabase) {
      // Demo mode
      const demoUser = { id: 'demo-user', email } as User
      setUser(demoUser)
      localStorage.setItem(DEMO_USER_KEY, JSON.stringify(demoUser))
      return { error: null }
    }
    
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    })
    
    return { error }
  }

  const signOut = async () => {
    try {
      if (!supabase) {
        setUser(null)
        localStorage.removeItem(DEMO_USER_KEY)
        return { success: true }
      }
      
      setUser(null)
      setSession(null)
      setUserPermissions(null)
      await supabase.auth.signOut()
      
      return { success: true }
    } catch (error) {
      return { success: false, error }
    }
  }

  const value = {
    user,
    session,
    userPermissions,
    loading,
    signIn,
    signUp,
    signOut,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}