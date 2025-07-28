module.exports = {
  apps: [{
    name: 'screenshot-api',
    script: 'server.js',
    instances: 'max', // Use all available CPU cores
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    // Restart policy
    restart_delay: 4000,
    max_restarts: 10,
    min_uptime: '10s',
    
    // Memory and CPU limits
    max_memory_restart: '1G',
    
    // Logging
    log_file: './logs/combined.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Advanced features
    watch: false,
    ignore_watch: ['node_modules', 'screenshots', 'logs'],
    
    // Health monitoring
    health_check_grace_period: 3000,
    health_check_fatal_exceptions: true,
    
    // Environment variables
    env_file: '.env',
    
    // Process management
    kill_timeout: 5000,
    listen_timeout: 3000,
    
    // Resource monitoring
    monitoring: true,
    
    // Autorestart conditions
    autorestart: true,
    
    // Graceful start/shutdown
    wait_ready: true,
    
    // Instance variables
    instance_var: 'INSTANCE_ID'
  }],

  deploy: {
    production: {
      user: 'deploy',
      host: 'your-server.com',
      ref: 'origin/main',
      repo: 'git@github.com:AbdelrahmanM1/Screenshot-Generator-API.git',
      path: '/var/www/screenshot-api',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': '',
      'ssh_options': 'ForwardAgent=yes'
    }
  }
};