import { Link, useLocation } from 'react-router-dom';

export function Sidebar() {
  const location = useLocation();
  
  const navItems = [
    { path: '/dashboard', label: 'Dashboard' },
    { path: '/traffic', label: 'Traffic' },
    { path: '/analysis', label: 'Analysis' },
    { path: '/findings', label: 'Findings' },
    { path: '/sessions', label: 'Sessions' },
    { path: '/devices', label: 'Devices' },
    { path: '/settings', label: 'Settings' },
  ];
  
  return (
    <div className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700">
      <div className="p-4">
        <h1 className="text-xl font-bold">AX-TrafficAnalyzer</h1>
      </div>
      <nav className="mt-4">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`block px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 ${
              location.pathname === item.path ? 'bg-gray-100 dark:bg-gray-700' : ''
            }`}
          >
            {item.label}
          </Link>
        ))}
      </nav>
    </div>
  );
}

