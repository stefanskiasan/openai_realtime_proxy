module.exports = {
  apps: [{
    name: 'voice-proxy',
    script: './dist/server.js',
    instances: process.env.PM2_INSTANCES || 'max',
    exec_mode: 'cluster',
    
    env: {
      NODE_ENV: 'production',
      PORT: process.env.PORT || 8080
    },
    
    error_file: './logs/error.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    
    max_memory_restart: '1G',
    min_uptime: '10s',
    max_restarts: 10,
    
    kill_timeout: 5000,
    wait_ready: true,
    listen_timeout: 3000,
    
    instance_var: 'INSTANCE_ID',
    merge_logs: true,
    
    autorestart: true,
    watch: false,
    
    node_args: '--max-old-space-size=1024'
  }]
};