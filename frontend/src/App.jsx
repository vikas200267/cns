import React, { useState, useEffect } from 'react';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import LoginPage from './components/LoginPage';
import RegisterPage from './components/RegisterPage';
import LabControlApp from './LabControlApp';

// API URL Configuration
const getApiUrl = () => {
  if (process.env.NODE_ENV === 'development') {
    return '';  // Use proxy
  }
  
  const isLocalhost = window.location.hostname === 'localhost' || 
                      window.location.hostname === '127.0.0.1' ||
                      window.location.hostname === '0.0.0.0';
  
  if (isLocalhost) {
    return 'http://localhost:3001';
  }
  
  if (process.env.REACT_APP_BACKEND_URL) {
    return process.env.REACT_APP_BACKEND_URL;
  }
  
  if (window.location.hostname.includes('github.dev') || window.location.hostname.includes('app.github.dev')) {
    return window.location.origin.replace('-3000.', '-3001.');
  }
  
  return 'http://localhost:3001';
};

const API_URL = getApiUrl();

const App = () => {
  const [currentPage, setCurrentPage] = useState('login'); // 'login', 'register', 'dashboard'
  const [user, setUser] = useState(null);
  const [authToken, setAuthToken] = useState(null);

  // Check for existing authentication on mount
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const storedUser = localStorage.getItem('user');

    if (token && storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser);
        setAuthToken(token);
        setUser(parsedUser);
        setCurrentPage('dashboard');
      } catch (error) {
        console.error('Error parsing stored user:', error);
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
      }
    }
  }, []);

  const handleLoginSuccess = (userData, token) => {
    setUser(userData);
    setAuthToken(token);
    setCurrentPage('dashboard');
  };

  const handleRegisterSuccess = (userData, token) => {
    setUser(userData);
    setAuthToken(token);
    setCurrentPage('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    setUser(null);
    setAuthToken(null);
    setCurrentPage('login');
  };

  return (
    <>
      {currentPage === 'login' && (
        <LoginPage
          onLoginSuccess={handleLoginSuccess}
          onSwitchToRegister={() => setCurrentPage('register')}
          apiUrl={API_URL}
        />
      )}

      {currentPage === 'register' && (
        <RegisterPage
          onRegisterSuccess={handleRegisterSuccess}
          onSwitchToLogin={() => setCurrentPage('login')}
          apiUrl={API_URL}
        />
      )}

      {currentPage === 'dashboard' && user && (
        <LabControlApp 
          user={user}
          authToken={authToken}
          onLogout={handleLogout}
        />
      )}

      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="dark"
      />
    </>
  );
};

export default App;
