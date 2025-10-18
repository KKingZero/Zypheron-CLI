#!/bin/bash

echo ""
echo "===================================="
echo " 🐍 COBRA AI - Starting Application"
echo "===================================="
echo ""
echo "Starting CobraAI with all security microservices..."
echo ""
echo "Services that will be automatically started:"
echo " 🐍 OSINT Service (Port 8001)"
echo " 🔍 Scanner Service with Nikto, SQLMap, John the Ripper (Port 8002)"
echo " 📦 Packet Manipulator Service (Port 8003)"
echo " 🕷️ Web Crawler Service (Port 8004)"
echo " 🔓 Brute Force Service (Port 8005)"
echo " 🐍 Main Backend API (Port 3001)"
echo " ⚡ Frontend UI (Port 5173)"
echo ""
echo "Please wait while all services initialize..."
echo ""

npm run dev:all