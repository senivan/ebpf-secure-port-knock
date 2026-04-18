#!/usr/bin/env python3
"""Main entry point for the admin panel backend"""

import os
import sys
from app import create_app

if __name__ == '__main__':
    app = create_app()
    
    port = int(os.getenv('API_PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║     eBPF Secure Port Knock - Admin Panel API                ║
    ║                                                              ║
    ║  Starting server on port {port}                              ║
    ║  Debug mode: {'ON' if debug else 'OFF'}                              ║
    ║                                                              ║
    ║  Endpoints available at http://localhost:{port}/api           ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
