import { useAuthStore } from '../../stores/authStore';
import { Button } from '../ui/button';

export function Header() {
  const { user, logout } = useAuthStore();
  
  return (
    <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-between">
      <h2 className="text-lg font-semibold">Welcome, {user?.user_id || 'User'}</h2>
      <Button onClick={logout}>
        Logout
      </Button>
    </header>
  );
}

