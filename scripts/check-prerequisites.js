#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🐍 COBRA AI Prerequisites Checker\n');

const prerequisites = [
  {
    name: 'Node.js',
    command: 'node --version',
    required: true,
    installUrl: 'https://nodejs.org/'
  },
  {
    name: 'Python',
    command: 'python --version',
    required: true,
    installUrl: 'https://www.python.org/downloads/',
    alternatives: ['python3 --version']
  },
  {
    name: 'Rust',
    command: 'cargo --version',
    required: false,
    installUrl: 'https://rustup.rs/'
  },
  {
    name: 'Go',
    command: 'go version',
    required: false,
    installUrl: 'https://golang.org/dl/'
  },
  {
    name: 'CMake',
    command: 'cmake --version',
    required: false,
    installUrl: 'https://cmake.org/download/'
  },
  {
    name: 'C++ Compiler (GCC/Clang)',
    command: process.platform === 'win32' ? 'cl' : 'gcc --version',
    required: false,
    installUrl: process.platform === 'win32' 
      ? 'https://visualstudio.microsoft.com/downloads/' 
      : 'https://gcc.gnu.org/'
  }
];

function checkCommand(command) {
  try {
    execSync(command, { stdio: 'ignore' });
    return true;
  } catch (error) {
    return false;
  }
}

function checkPrerequisite(prereq) {
  let available = checkCommand(prereq.command);
  
  // Try alternatives if main command fails
  if (!available && prereq.alternatives) {
    for (const alt of prereq.alternatives) {
      if (checkCommand(alt)) {
        available = true;
        break;
      }
    }
  }
  
  const status = available ? '✅' : (prereq.required ? '❌' : '⚠️');
  const statusText = available ? 'Available' : (prereq.required ? 'REQUIRED - Missing' : 'Optional - Missing');
  
  console.log(`${status} ${prereq.name}: ${statusText}`);
  
  if (!available && !prereq.required) {
    console.log(`   └─ Install from: ${prereq.installUrl}`);
  } else if (!available && prereq.required) {
    console.log(`   └─ INSTALL REQUIRED: ${prereq.installUrl}`);
  }
  
  return { name: prereq.name, available, required: prereq.required };
}

console.log('Checking prerequisites...\n');

const results = prerequisites.map(checkPrerequisite);

console.log('\n📋 Summary:');
console.log('═══════════');

const missing = results.filter(r => !r.available);
const missingRequired = missing.filter(r => r.required);
const missingOptional = missing.filter(r => !r.required);

if (missingRequired.length === 0) {
  console.log('✅ All required prerequisites are available!');
} else {
  console.log(`❌ Missing required: ${missingRequired.map(r => r.name).join(', ')}`);
}

if (missingOptional.length > 0) {
  console.log(`⚠️  Missing optional: ${missingOptional.map(r => r.name).join(', ')}`);
  console.log('   └─ Some services will not be available without these.');
}

console.log('\n🚀 Available npm commands:');
console.log('═════════════════════════════');
console.log('npm run dev           - Frontend + Backend only');
console.log('npm run dev:all       - All services (if prerequisites met)');
console.log('npm run services      - All microservices only');
console.log('npm run all           - Everything (frontend, backend, services)');
console.log('npm run setup         - Install all dependencies');
console.log('');
console.log('Individual services:');
console.log('npm run dev:osint              - Python OSINT service');
console.log('npm run dev:scanner            - Rust network scanner');
console.log('npm run dev:crawler            - Go web crawler');
console.log('npm run dev:packet-manipulator - C++ packet manipulator');

console.log('\n💡 Quick start:');
console.log('1. Install missing prerequisites');
console.log('2. Run: npm run setup');
console.log('3. Run: npm run all');

if (missingRequired.length > 0) {
  process.exit(1);
} 