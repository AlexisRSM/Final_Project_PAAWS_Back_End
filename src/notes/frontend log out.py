function logout() {
    fetch('/logout', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    })
    .then(response => {
        if (response.ok) {
            localStorage.removeItem('token');
            // Redirect user or update UI
        }
    });
}
#example react
import React from 'react';

const LogoutButton = () => {
  const handleLogout = () => {
    fetch('/logout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    })
    .then(response => {
      if (response.ok) {
        localStorage.removeItem('token');
        // Redirect user or update UI
        window.location.href = '/login'; // Redirect to login or any other page
      } else {
        // Handle errors if needed
        console.error('Logout failed');
      }
    })
    .catch(error => {
      console.error('Error:', error);
    });
  };

  return (
    <button onClick={handleLogout}>
      Logout
    </button>
  );
};

export default LogoutButton;
