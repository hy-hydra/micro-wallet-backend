module.exports = {
  apps: [
    {
      name: 'marcowallet-app', // Change this to your app name
      script: 'manage.py',
      args: ['runserver', '0.0.0.0:8000'], // Change this to your Django runserver command
      interpreter: 'python3', // Change this to your Python interpreter path if necessary
      autorestart: true,
      watch: true,
      ignore_watch: ['static', 'media'], // Ignore these directories
      watch_options: {
        followSymlinks: false,
      },
    },
  ],
};
