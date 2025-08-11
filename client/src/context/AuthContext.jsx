// context/AuthContext.js
import React, { createContext, useState, useEffect } from 'react';
import api from '../utils/api';
import { toast } from 'react-toastify';

const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  // Initialize user from localStorage if available
  const [user, setUser] = useState(() => {
    const storedUser = localStorage.getItem('user');
    return storedUser ? JSON.parse(storedUser) : null;
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) {
          setUser(null);
          localStorage.removeItem('user');
          setLoading(false);
          return;
        }
        const res = await api.get('/auth/check-auth', { withCredentials: true });
        if (res.data && res.data.user) {
          setUser(res.data.user);
          localStorage.setItem('user', JSON.stringify(res.data.user));
        } else {
          setUser(null);
          localStorage.removeItem('user');
        }
      } catch (err) {
        setUser(null);
        localStorage.removeItem('user');
        localStorage.removeItem('token');
      } finally {
        setLoading(false);
      }
    };
    checkAuth();
    // Listen for localStorage changes (multi-tab sync)
    const handleStorage = (e) => {
      if (e.key === 'user') {
        setUser(e.newValue ? JSON.parse(e.newValue) : null);
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, []);

  const login = async (email, password, role) => {
    try {
      let endpoint;
      if (role === 'student') {
        endpoint = '/auth/student-login';
      } else if (role === 'authority') {
        endpoint = '/auth/authority-login';
      } else if (role === 'admin') {
        endpoint = '/auth/admin-login';
      } else throw new Error('Invalid role');

      const res = await api.post(endpoint, { email, password }, { withCredentials: true });
      localStorage.setItem('token', res.data.token);

      const userData = {
        ...res.data.user,
        role,
        designation: res.data.user?.designation || null,
        department:
          res.data.user?.designation === 'Network Department'
            ? 'Network'
            : res.data.user?.department || null,
        hostelNo:
          res.data.user?.designation === 'Network Department'
            ? null
            : res.data.user?.hostelNo || null
      };

      setUser(userData);
      localStorage.setItem('user', JSON.stringify(userData));
      toast.success('Logged in successfully');
      return userData;
    } catch (error) {
      toast.error(error.response?.data?.message || 'Login failed');
      throw error;
    }
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout', {}, { withCredentials: true });
    } catch (error) {
      // Optionally handle error
    } finally {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, setUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export { AuthContext, AuthProvider };
